package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// The v0.5 dangerous-cap_add validator (ROADMAP §v0.5, CL-0011) is the inverse
// of the v0.1 capability observer: v0.1 derives the minimum cap_add from zero;
// v0.5 takes an already-granted dangerous cap and validates it against runtime
// behavior — which syscalls actually invoked it, whether a finer-grained
// capability would suffice, and whether it was granted but never exercised.
//
// It reuses the v0.1 trace_capabilities signal and the capEvent attribution
// (a dangerous-cap use is just a held cap_capable check whose `cap` is in the
// validate-set). No new gadget: the cap→syscall correlation is a re-aggregation
// of the same stream, keyed on syscall instead of deduped to a cap set. The
// per-event `syscall` field is present at the pinned IG v0.51.0 (verified in
// testdata/ig-versions/v0.51.0/sample.ndjson). Design + scope in issue #111.

// dangerousCaps is the default validate-set: the high-risk capabilities whose
// presence in cap_add warrants scrutiny (container-escape / broad host impact
// potential). It deliberately EXCLUDES the routine de-escalation caps a normal
// entrypoint legitimately uses at startup (CHOWN, SETUID, SETGID, SETPCAP,
// FOWNER, FSETID, KILL, NET_BIND_SERVICE, AUDIT_WRITE) so the default report is
// signal, not noise. When the user passes --cap-add the explicit set overrides
// this default. Names are normalized (no CAP_ prefix), matching normalizeCap.
var dangerousCaps = map[string]struct{}{
	"SYS_ADMIN":          {},
	"SYS_MODULE":         {},
	"SYS_RAWIO":          {},
	"SYS_PTRACE":         {},
	"SYS_BOOT":           {},
	"SYS_TIME":           {},
	"SYS_RESOURCE":       {},
	"SYS_NICE":           {},
	"SYS_CHROOT":         {},
	"DAC_READ_SEARCH":    {},
	"DAC_OVERRIDE":       {},
	"CHECKPOINT_RESTORE": {},
	"NET_ADMIN":          {},
	"NET_RAW":            {},
	"MKNOD":              {},
	"LINUX_IMMUTABLE":    {},
	"MAC_ADMIN":          {},
	"MAC_OVERRIDE":       {},
	"SYSLOG":             {},
	"AUDIT_CONTROL":      {},
	"BPF":                {},
	"PERFMON":            {},
	"SETFCAP":            {},
	"WAKE_ALARM":         {},
	"BLOCK_SUSPEND":      {},
}

// capUsage collapses the held cap_capable events for one capability into the
// numbers the validation + sidecar need: which syscalls invoked it (with
// per-syscall counts), the distinct comms, and the total held-event count.
type capUsage struct {
	syscalls map[string]int      // syscall name -> held-event count
	comms    map[string]struct{} // distinct comm samples
	events   int                 // total held events for this cap
}

// capaddObservation is the v0.5 aggregate: per-capability usage for the caps in
// the active validate-set, plus the multi-replica bookkeeping (union members and
// per-replica cap sets) that mirrors the cap/fs/device aggregators. The decision
// layer (capaddToValidation) turns this into findings + a recommended cap_add.
type capaddObservation struct {
	Used       map[string]*capUsage // normalized cap -> usage (held, post-init-filter)
	EventCount int                  // held dangerous-cap events counted post-filter
	Dropped    int                  // ig ringbuf-lost count (live path); 0 in fixture mode

	// Denied records denied (capable:false) cap_capable attempts per cap
	// (normalized) -> syscall -> count, for caps in the active set, after the
	// same target/init filtering as held usage. A denied check says nothing
	// about a *held* cap's exercise, so these are NOT counted as usage (they
	// never enter Used/EventCount). But they ARE retained as evidence of
	// *attempted* use: a denied broad syscall under a granted cap means the
	// decision layer must not silently recommend dropping or finer-substituting
	// it on the strength of the held syscalls alone (deep-review L10).
	Denied map[string]map[string]int

	// PerReplica is the set of in-validate-set caps observed per replica id
	// (or name), feeding the multi-replica disagreement signal. PerReplicaCount
	// is the held-event count per replica (the per_replica_event_counts source).
	PerReplica      map[string][]string
	PerReplicaCount map[string]int

	Image string // first observed container image, mirroring the other aggregators
}

// aggregateCapadd reads trace_capabilities NDJSON from r, keeps held
// (capable:true) events that match the target selector and whose normalized cap
// is in activeSet, drops runc/init bring-up checks (isInitComm — a dangerous cap
// used only by runc:[*] during container setup is not the workload's need), and
// records per-cap syscall usage. The >1-replica ambiguity guard mirrors
// aggregate()/aggregateDevices exactly: --image matching multiple replicas
// without --all-matching is refused rather than silently unioned.
func aggregateCapadd(r io.Reader, opts aggregateOpts, activeSet map[string]struct{}) (*capaddObservation, error) {
	used := map[string]*capUsage{}
	denied := map[string]map[string]int{}
	perReplica := map[string]map[string]struct{}{}
	perReplicaCount := map[string]int{}
	perReplicaName := map[string]string{}
	count := 0
	image := ""
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	for scan.Scan() {
		line := scan.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev capEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("parse trace_capabilities event: %w", err)
		}
		// Target + init + active-set filtering applies to held AND denied events
		// alike: an off-target, runc/init, or out-of-set check is noise either
		// way. (This filtering used to short-circuit on !Capable before matching;
		// it now matches first so a denied in-scope attempt can be retained — L10.)
		if !opts.matches(ev) {
			continue
		}
		if isInitComm(ev.Proc.Comm) {
			// runc/init bring-up noise: a dangerous cap used only during
			// container setup is not the workload's requirement.
			continue
		}
		cap := normalizeCap(ev.CapName)
		if _, ok := activeSet[cap]; !ok {
			continue
		}
		if !ev.Capable {
			// Denied check: the cap was NOT held here. It does not count as
			// usage (mirrors the v0.1 aggregator, which drops denied checks so
			// they can't inflate the derived set), but we retain the attempted
			// syscall as an L10 signal so the decision layer won't drop or
			// finer-substitute a cap the workload tried — and was denied — to use.
			if sc := strings.TrimSpace(ev.Syscall); sc != "" {
				if denied[cap] == nil {
					denied[cap] = map[string]int{}
				}
				denied[cap][sc]++
			}
			continue
		}
		count++
		if image == "" {
			image = ev.Runtime.ContainerImage
		}
		u := used[cap]
		if u == nil {
			u = &capUsage{syscalls: map[string]int{}, comms: map[string]struct{}{}}
			used[cap] = u
		}
		u.events++
		if sc := strings.TrimSpace(ev.Syscall); sc != "" {
			u.syscalls[sc]++
		}
		if comm := strings.TrimSpace(ev.Proc.Comm); comm != "" {
			u.comms[comm] = struct{}{}
		}

		rid := ev.Runtime.ContainerID
		if rid == "" {
			rid = ev.Runtime.ContainerName
		}
		if perReplica[rid] == nil {
			perReplica[rid] = map[string]struct{}{}
		}
		perReplica[rid][cap] = struct{}{}
		perReplicaCount[rid]++
		if ev.Runtime.ContainerName != "" {
			perReplicaName[rid] = ev.Runtime.ContainerName
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}

	// Ambiguity: the selector (--image, or a too-short --container prefix)
	// matched >1 replica without --all-matching. Same guard as
	// aggregate()/aggregateDevices — refuse to silently union the dangerous-cap
	// usage of replicas the user didn't opt into aggregating.
	if opts.ambiguous(len(perReplica)) {
		labels := make([]string, 0, len(perReplica))
		for rid := range perReplica {
			if name := perReplicaName[rid]; name != "" {
				labels = append(labels, fmt.Sprintf("%s (%s)", name, rid))
			} else {
				labels = append(labels, rid)
			}
		}
		sort.Strings(labels)
		return nil, opts.newAmbiguousSelectionError(labels)
	}

	obs := &capaddObservation{
		Used:            used,
		Denied:          denied,
		EventCount:      count,
		PerReplica:      map[string][]string{},
		PerReplicaCount: perReplicaCount,
		Image:           image,
	}
	for rid, set := range perReplica {
		obs.PerReplica[rid] = sortedKeys(set)
	}
	return obs, nil
}

// parseCapSet normalizes a comma-separated cap list (--cap-add) into a set of
// CAP_-stripped, upper-cased names. Empty/blank entries are skipped. Returns nil
// for an empty input so callers can distinguish "no explicit set" from "set".
func parseCapSet(s string) map[string]struct{} {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := map[string]struct{}{}
	for _, part := range strings.Split(s, ",") {
		if c := normalizeCap(part); c != "" {
			out[c] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
