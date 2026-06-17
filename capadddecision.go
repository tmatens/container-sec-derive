package main

import (
	"fmt"
	"sort"
	"strings"
)

// The v0.5 decision layer turns observed dangerous-cap usage into a validation:
// per cap, whether it was used (and by which syscalls), an honest advisory, any
// concrete finer-grained substitute, and — when the user supplied the granted
// set (--cap-add) — a recommended minimized cap_add.
//
// The knowledge base is deliberately CONSERVATIVE. Where a finer capability
// genuinely covers the observed syscalls it is named as a substitution; where
// none exists the advice says so plainly rather than inventing one. This is
// reference guidance, not an authoritative "safe to drop": every conclusion is
// workload-bounded (the standing Caveat), and the unused -> removable call is the
// sharpest edge — the v0.5 analog of csd verify's over_permissioned WARN.

// SyscallStat is one syscall that invoked a held cap_capable check for a
// capability, with its held-event count. Sorted by name in a finding.
type SyscallStat struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// CapaddFinding is the validation verdict for one capability in the validate-set.
// Used=false with Removable=true means the cap was explicitly granted (--cap-add)
// but no held check fired under the workload — a removal candidate. FinerCaps is
// the concrete substitute set when every observed syscall is covered by a
// finer-grained capability (e.g. SYS_ADMIN used only via perf_event_open ->
// PERFMON); empty otherwise.
type CapaddFinding struct {
	Cap        string        `json:"cap"`
	Used       bool          `json:"used"`
	Removable  bool          `json:"removable"`
	EventCount int           `json:"event_count"`
	Syscalls   []SyscallStat `json:"syscalls"`
	Advice     string        `json:"advice"`
	FinerCaps  []string      `json:"finer_caps,omitempty"`
}

// capaddValidation is the v0.5 sidecar block. GrantedSetProvided records whether
// the user passed --cap-add (the explicit granted set): only then can unused caps
// be flagged and a RecommendedCapAdd synthesized. Without it the validator
// reports only the dangerous caps actually observed in use, and RecommendedCapAdd
// is empty (there is no granted set to rewrite).
type capaddValidation struct {
	Findings           []CapaddFinding `json:"findings"`
	GrantedSetProvided bool            `json:"granted_set_provided"`
	RecommendedCapAdd  []string        `json:"recommended_cap_add"`
}

// capKBEntry is one capability's knowledge-base entry: an honest base advisory
// for when no clean finer substitution applies, and an optional per-syscall map
// to a finer capability. A substitution is offered ONLY when every observed
// syscall is covered by the map — a SYS_ADMIN that fired for both perf_event_open
// (-> PERFMON) and mount (no finer cap) is not safely reducible, so it falls
// through to the base advice.
type capKBEntry struct {
	base           string
	finerBySyscall map[string]string
}

// capKB is the curated dangerous-capability knowledge base. Entries are honest:
// where no finer capability exists the advice says so. Names are normalized
// (no CAP_ prefix). Caps absent from the table get a generic advisory.
var capKB = map[string]capKBEntry{
	"SYS_ADMIN": {
		base: "the kitchen-sink capability; no single finer capability covers it. Narrow via the observed syscalls — e.g. BPF program loading typically needs CAP_BPF *plus* a program-type cap (CAP_PERFMON for kprobe/perf, CAP_NET_ADMIN for tc/xdp), so it is NOT safely replaced by CAP_BPF alone; otherwise consider rootless / user-namespace alternatives or a scoped seccomp profile.",
		// Only perf_event_open maps to a single finer cap. `bpf` is deliberately
		// NOT mapped: loading most BPF objects needs CAP_BPF + CAP_PERFMON (or
		// CAP_NET_ADMIN) depending on program type, so recommending CAP_BPF
		// alone would drop a still-needed cap (deep-review M4) — it falls through
		// to the honest base advice above instead.
		finerBySyscall: map[string]string{
			"perf_event_open": "PERFMON",
		},
	},
	"SYS_PTRACE":         {base: "process introspection (ptrace / process_vm_readv); no finer capability exists. Restrict to debugging builds rather than shipping it in production."},
	"SYS_MODULE":         {base: "loads / unloads kernel modules; load required modules on the host instead — almost never legitimate inside a container."},
	"SYS_RAWIO":          {base: "raw I/O port and device-memory access (/dev/mem, ioperm); almost never legitimate in a container."},
	"SYS_TIME":           {base: "sets the system clock; let the host manage time (NTP) and drop this capability."},
	"SYS_BOOT":           {base: "reboot() / kexec_load(); not legitimate for an application container."},
	"SYS_NICE":           {base: "raises scheduling priority / sets CPU affinity; keep only if real-time or elevated nice priority is genuinely required."},
	"SYS_RESOURCE":       {base: "overrides resource limits and quotas; usually resolvable by setting the limits correctly on the container instead."},
	"SYS_CHROOT":         {base: "chroot(); rarely needed by application workloads — review whether the entrypoint actually requires it."},
	"DAC_OVERRIDE":       {base: "bypasses all file read / write / execute permission checks; usually resolvable by chowning files to the container's runtime user."},
	"DAC_READ_SEARCH":    {base: "bypasses file-read and directory-search permission checks (and enables open_by_handle_at, a known container-escape primitive); prefer correct ownership / ACLs."},
	"CHECKPOINT_RESTORE": {base: "checkpoint/restore (criu) — also grants open_by_handle_at, the SAME container-escape primitive as DAC_READ_SEARCH (it was carved out of it); rarely needed by application workloads."},
	"NET_ADMIN":          {base: "network-stack configuration (interfaces, routes, iptables); no finer capability. If the need is only binding privileged ports, CAP_NET_BIND_SERVICE is sufficient."},
	"NET_RAW":            {base: "raw and packet sockets; no finer capability. If the only use is ICMP (ping), set net.ipv4.ping_group_range and drop NET_RAW entirely."},
	"MKNOD":              {base: "creates device nodes (mknod); rarely needed — pre-create required nodes or grant them via devices: instead."},
	"LINUX_IMMUTABLE":    {base: "sets the immutable / append-only inode flags; almost never needed by an application container."},
	"MAC_ADMIN":          {base: "configures the MAC (AppArmor / SELinux) policy; not legitimate for an application container."},
	"MAC_OVERRIDE":       {base: "overrides MAC (AppArmor / SELinux) policy; not legitimate for an application container."},
	"SYSLOG":             {base: "reads and controls the kernel ring buffer (dmesg); review whether the workload genuinely needs kernel log access."},
	"AUDIT_CONTROL":      {base: "configures the kernel audit subsystem; not legitimate for an application container."},
	"BPF":                {base: "loads BPF programs and maps; legitimate for observability / networking tooling but a broad capability — keep only if the workload is itself a BPF tool."},
	"PERFMON":            {base: "performance-monitoring access (perf_event_open); legitimate for profilers, but review whether the workload needs it in production."},
	"SETFCAP":            {base: "sets file capabilities; usually only needed by package / installer tooling at build time, not at runtime."},
	"WAKE_ALARM":         {base: "sets wake-from-suspend timers; not legitimate for a container on a server host."},
	"BLOCK_SUSPEND":      {base: "blocks system suspend; not legitimate for a container on a server host."},
}

// capAdvice returns the advisory for a used capability and, when every observed
// syscall is covered by a finer capability, the concrete substitute set.
// syscalls and deniedSyscalls are expected sorted; deniedSyscalls are the
// capable:false attempts retained for this cap (L10).
func capAdvice(capName string, syscalls, deniedSyscalls []string) (advice string, finerCaps []string) {
	entry, known := capKB[capName]
	syscallList := strings.Join(syscalls, ", ")

	// L10: a denied (capable:false) attempt for a syscall that this cap's
	// knowledge-base entry has NO finer substitute for is evidence the workload
	// tries to use the capability for something a finer cap can't cover. We only
	// reason about this when a finer substitution was on the table (the entry has
	// a finerBySyscall map) — for caps with no substitute there is nothing to
	// suppress and the base advice already keeps them. Such a "broad" denied
	// attempt suppresses the substitution and adds a caveat.
	var deniedBroad []string
	if known && len(entry.finerBySyscall) > 0 {
		for _, sc := range deniedSyscalls {
			if _, mapped := entry.finerBySyscall[sc]; !mapped {
				deniedBroad = append(deniedBroad, sc)
			}
		}
	}

	if known && len(entry.finerBySyscall) > 0 && len(syscalls) > 0 && len(deniedBroad) == 0 {
		finer := map[string]struct{}{}
		allMapped := true
		for _, sc := range syscalls {
			if c, ok := entry.finerBySyscall[sc]; ok {
				finer[c] = struct{}{}
			} else {
				allMapped = false
				break
			}
		}
		if allMapped {
			finerCaps = sortedKeys(finer)
			// Not a flat "is sufficient": the substitution is workload-bounded
			// and a finer cap may carry its own gate (deep-review M4/L9).
			advice = fmt.Sprintf("observed only via %s; %s likely suffices (Linux >= 5.8) — verify before dropping %s.",
				syscallList, strings.Join(finerCaps, " + "), capName)
			for _, fc := range finerCaps {
				if fc == "PERFMON" {
					advice += " (CAP_PERFMON is additionally gated by kernel.perf_event_paranoid.)"
					break
				}
			}
			return advice, finerCaps
		}
	}

	// Substitution suppressed (or never applicable): fall through to the honest
	// base advice, appending the L10 caveat when a denied broad attempt is what
	// blocked an otherwise-clean substitution.
	caveat := ""
	if len(deniedBroad) > 0 {
		caveat = fmt.Sprintf(" Note: denied (capable:false) attempt(s) observed via %s — the workload tried to use this capability for operation(s) no finer capability covers, so it cannot be safely substituted or dropped on the strength of the held syscalls alone.",
			strings.Join(deniedBroad, ", "))
	}
	if known {
		if syscallList != "" {
			return fmt.Sprintf("observed via %s. %s%s", syscallList, entry.base, caveat), nil
		}
		return entry.base + caveat, nil
	}
	if syscallList != "" {
		return fmt.Sprintf("observed via %s; review whether this capability is genuinely required by the workload.%s", syscallList, caveat), nil
	}
	return "review whether this capability is genuinely required by the workload." + caveat, nil
}

// capaddToValidation builds the v0.5 validation from observed usage. When the
// granted set is known (--cap-add) every cap in it gets a finding (used or
// unused) and a recommended minimized cap_add is synthesized: used caps map to
// their finer substitute if one exists, otherwise to themselves; unused caps are
// dropped. Without an explicit set, only the dangerous caps actually observed are
// reported and no recommendation is produced (there is no granted set to rewrite).
func capaddToValidation(obs *capaddObservation, activeSet map[string]struct{}, granted bool) *capaddValidation {
	v := &capaddValidation{
		Findings:           []CapaddFinding{},
		GrantedSetProvided: granted,
		RecommendedCapAdd:  []string{},
	}

	var capsToReport []string
	if granted {
		capsToReport = sortedKeys(activeSet)
	} else {
		capsToReport = sortedKeys(obs.Used)
	}

	recommend := map[string]struct{}{}
	for _, c := range capsToReport {
		u := obs.Used[c]
		deniedNames := sortedKeys(obs.Denied[c])
		if u == nil {
			// No held check fired. Normally a granted-but-unused cap is a removal
			// candidate — UNLESS the workload attempted it and the check was
			// denied (capable:false): that is evidence the cap is wanted under a
			// grant it could not exercise, so it is NOT safe to drop (L10). Keep
			// it and caveat instead of recommending removal. (u==nil is reached
			// only in granted mode; default mode reports only observed-used caps.)
			if len(deniedNames) > 0 {
				v.Findings = append(v.Findings, CapaddFinding{
					Cap:      c,
					Used:     false,
					Syscalls: []SyscallStat{},
					Advice: fmt.Sprintf("no held check fired, but denied (capable:false) attempt(s) observed via %s — the workload attempted this capability under a grant it could not exercise; do not drop it without verifying those paths.",
						strings.Join(deniedNames, ", ")),
				})
				recommend[c] = struct{}{}
				continue
			}
			v.Findings = append(v.Findings, CapaddFinding{
				Cap:       c,
				Used:      false,
				Removable: granted,
				Syscalls:  []SyscallStat{},
				Advice:    "no capability check fired under this workload — candidate for removal. Workload-bounded: verify with a fuller workload before dropping.",
			})
			continue
		}
		names := make([]string, 0, len(u.syscalls))
		for sc := range u.syscalls {
			names = append(names, sc)
		}
		sort.Strings(names)
		advice, finer := capAdvice(c, names, deniedNames)
		v.Findings = append(v.Findings, CapaddFinding{
			Cap:        c,
			Used:       true,
			EventCount: u.events,
			Syscalls:   syscallStats(u.syscalls),
			Advice:     advice,
			FinerCaps:  finer,
		})
		if len(finer) > 0 {
			for _, fc := range finer {
				recommend[fc] = struct{}{}
			}
		} else {
			recommend[c] = struct{}{}
		}
	}
	if granted {
		v.RecommendedCapAdd = sortedKeys(recommend)
	}
	return v
}

// syscallStats turns a syscall->count map into a name-sorted SyscallStat slice.
func syscallStats(m map[string]int) []SyscallStat {
	out := make([]SyscallStat, 0, len(m))
	for name, count := range m {
		out = append(out, SyscallStat{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
