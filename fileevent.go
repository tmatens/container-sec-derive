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

// Open-flag constants (asm-generic ABI — amd64 and arm64, csd's two release
// arches, agree on these values; some other arches differ, but the vendored
// ig binary only ships for those two). Used to classify write-intent opens
// from trace_open's numeric flags_raw field.
const (
	oAccMode = 0x3    // mask for the access mode (low two bits)
	oRdOnly  = 0x0    // O_RDONLY
	oWrOnly  = 0x1    // O_WRONLY
	oRdWr    = 0x2    // O_RDWR
	oCreat   = 0o100  // O_CREAT
	oTrunc   = 0o1000 // O_TRUNC
	oAppend  = 0o2000 // O_APPEND
)

// fileEvent is the subset of ig trace_open fields csd's v0.2 read-only-fs
// observer consumes at PINNED_IG_VERSION. It shares trace_capabilities'
// event envelope (proc/runtime/timestamp_raw — see capEvent) and adds the
// open-specific fields: the syscall, the open flags (numeric flags_raw is
// authoritative; the decoded flags string is a fixture/fallback form), the
// path as given (fname) and the symlink-resolved path (fpath, populated only
// when ig runs with --paths), and the syscall error.
//
// As with capEvent, UnmarshalJSON is lenient so hand-rolled fixtures need not
// carry every field the live gadget emits.
type fileEvent struct {
	Timestamp int64  // milliseconds
	Syscall   string // "openat" / "open"
	FlagsRaw  int64  // numeric open flags (authoritative when HasFlagsRaw)
	// HasFlagsRaw distinguishes "flags_raw absent" from "flags_raw == 0"
	// (which is O_RDONLY): a zero value would otherwise be ambiguous, the
	// same reason capEvent uses a *bool for `capable`.
	HasFlagsRaw bool
	Flags       string // decoded flags, e.g. "O_WRONLY|O_CREAT" (fallback)
	Fname       string // path as given to the open syscall
	Fpath       string // symlink-resolved full path (requires ig --paths)
	ErrorRaw    int    // syscall errno (0 = success)
	Proc        struct {
		Comm string
		Pid  int
	}
	Runtime struct {
		ContainerID    string
		ContainerName  string
		ContainerImage string
		RuntimeName    string
	}
}

func (e *fileEvent) UnmarshalJSON(data []byte) error {
	type procT struct {
		Comm string `json:"comm"`
		Pid  int    `json:"pid"`
	}
	type runtimeT struct {
		ContainerID    string `json:"containerId"`
		ContainerName  string `json:"containerName"`
		ContainerImage string `json:"containerImageName"`
		RuntimeName    string `json:"runtimeName"`
	}
	var wire struct {
		Timestamp    json.RawMessage `json:"timestamp"`
		TimestampRaw int64           `json:"timestamp_raw"`
		Syscall      string          `json:"syscall"`
		FlagsRaw     *int64          `json:"flags_raw"`
		Flags        string          `json:"flags"`
		Fname        string          `json:"fname"`
		Fpath        string          `json:"fpath"`
		ErrorRaw     int             `json:"error_raw"`
		Proc         procT           `json:"proc"`
		Runtime      runtimeT        `json:"runtime"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	e.Syscall = wire.Syscall
	if wire.FlagsRaw != nil {
		e.FlagsRaw = *wire.FlagsRaw
		e.HasFlagsRaw = true
	}
	e.Flags = wire.Flags
	e.Fname = wire.Fname
	e.Fpath = wire.Fpath
	e.ErrorRaw = wire.ErrorRaw
	e.Proc.Comm, e.Proc.Pid = wire.Proc.Comm, wire.Proc.Pid
	e.Runtime.ContainerID = wire.Runtime.ContainerID
	e.Runtime.ContainerName = wire.Runtime.ContainerName
	e.Runtime.ContainerImage = wire.Runtime.ContainerImage
	e.Runtime.RuntimeName = wire.Runtime.RuntimeName
	switch {
	case wire.TimestampRaw != 0:
		e.Timestamp = wire.TimestampRaw / 1_000_000 // ns → ms (live ig)
	case len(wire.Timestamp) > 0:
		var n int64
		_ = json.Unmarshal(wire.Timestamp, &n) // fixture: bare ms int
		e.Timestamp = n
	}
	return nil
}

// Path returns the best path for the event: the symlink-resolved fpath when
// ig was run with --paths, else the raw fname. The v0.2 observer always runs
// with --paths, so live events carry fpath; the fname fallback keeps
// fpath-less fixtures usable.
func (e fileEvent) Path() string {
	if e.Fpath != "" {
		return e.Fpath
	}
	return e.Fname
}

// IsWrite reports whether the open expresses write intent — the access mode is
// O_WRONLY/O_RDWR, or O_CREAT/O_TRUNC/O_APPEND is set (O_RDONLY|O_CREAT still
// creates a file). This is the v0.2 filter: a read-only open does not require
// a writable filesystem. When flags_raw is present it is authoritative; for
// fixtures carrying only the decoded `flags` string, the tokens are parsed.
func (e fileEvent) IsWrite() bool {
	if e.HasFlagsRaw {
		if e.FlagsRaw&oAccMode == oWrOnly || e.FlagsRaw&oAccMode == oRdWr {
			return true
		}
		return e.FlagsRaw&(oCreat|oTrunc|oAppend) != 0
	}
	for _, tok := range strings.Split(e.Flags, "|") {
		switch strings.TrimSpace(tok) {
		case "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND":
			return true
		}
	}
	return false
}

// writeObservation is the v0.2 file-write observer's aggregate: the distinct
// write-intent paths observed (unioned and per-replica) plus the count of
// write events behind them. It is deliberately thinner than the capability
// aggregate()/Sidecar — beta layers volume correlation, the read_only/tmpfs
// decision, and the sidecar/confidence integration on top (issue #77).
type writeObservation struct {
	Paths      []string            // sorted union of write-intent paths
	PerReplica map[string][]string // replica id (or name) -> sorted write paths
	EventCount int                 // write-intent events counted post-filter

	// PerReplicaCount is the write-event count per replica (the cap
	// aggregator's per_replica_event_counts analog), populated alongside
	// PerReplica so reviewers can see uneven coverage across replicas.
	PerReplicaCount map[string]int
	// Stats is per-path detail (event count + comm samples) feeding the
	// sidecar's writable_paths section — the WritablePath analog of capStats.
	Stats map[string]*writeStats
	// Dropped is ig's ringbuf-lost-sample count for the live observe path
	// (set by observeWrites); 0 in fixture mode. Feeds trace_health.
	Dropped int
	// Image is the first observed container image (populates Sidecar.Image
	// when --image was not the selector), mirroring the cap aggregator.
	Image string
}

// writeStats collapses N write opens for one path into the numbers the
// sidecar's writable_paths section needs. Mirrors capStats but thinner —
// the fs observer has no per-path timing requirement yet.
type writeStats struct {
	eventCount  int
	commSamples map[string]struct{}
}

// aggregateWrites reads trace_open NDJSON from r, keeps events that match the
// target selector (aggregateOpts.matchesRuntime) and express write intent
// (fileEvent.IsWrite), and collects their paths per replica and unioned.
// Replica identity mirrors the cap aggregator: container id, falling back to
// name when id is empty (hand-rolled fixtures). A malformed line is a hard
// error, as in aggregate().
func aggregateWrites(r io.Reader, opts aggregateOpts) (*writeObservation, error) {
	union := map[string]struct{}{}
	perReplica := map[string]map[string]struct{}{}
	perReplicaCount := map[string]int{}
	perReplicaName := map[string]string{}
	stats := map[string]*writeStats{}
	count := 0
	image := ""
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	for scan.Scan() {
		line := scan.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev fileEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("parse trace_open event: %w", err)
		}
		if !opts.matchesRuntime(ev.Runtime.ContainerID, ev.Runtime.ContainerName, ev.Runtime.ContainerImage) {
			continue
		}
		if !ev.IsWrite() {
			continue
		}
		p := ev.Path()
		if p == "" {
			continue
		}
		count++
		if image == "" {
			image = ev.Runtime.ContainerImage
		}
		union[p] = struct{}{}
		rid := ev.Runtime.ContainerID
		if rid == "" {
			rid = ev.Runtime.ContainerName
		}
		if perReplica[rid] == nil {
			perReplica[rid] = map[string]struct{}{}
		}
		perReplica[rid][p] = struct{}{}
		perReplicaCount[rid]++
		if ev.Runtime.ContainerName != "" {
			perReplicaName[rid] = ev.Runtime.ContainerName
		}
		st := stats[p]
		if st == nil {
			st = &writeStats{commSamples: map[string]struct{}{}}
			stats[p] = st
		}
		st.eventCount++
		if comm := strings.TrimSpace(ev.Proc.Comm); comm != "" {
			st.commSamples[comm] = struct{}{}
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}

	// Ambiguity: --image matched >1 replica without --all-matching. Mirrors
	// aggregate() (the cap path) — the tool refuses to silently union the
	// write paths of replicas the user didn't opt into aggregating.
	if opts.Image != "" && !opts.AllMatching && len(perReplica) > 1 {
		labels := make([]string, 0, len(perReplica))
		for rid := range perReplica {
			if name := perReplicaName[rid]; name != "" {
				labels = append(labels, fmt.Sprintf("%s (%s)", name, rid))
			} else {
				labels = append(labels, rid)
			}
		}
		sort.Strings(labels)
		return nil, &ambiguousSelectionError{image: opts.Image, replicas: labels}
	}

	obs := &writeObservation{
		Paths:           sortedKeys(union),
		PerReplica:      map[string][]string{},
		EventCount:      count,
		PerReplicaCount: perReplicaCount,
		Stats:           stats,
		Image:           image,
	}
	for rid, set := range perReplica {
		obs.PerReplica[rid] = sortedKeys(set)
	}
	return obs, nil
}
