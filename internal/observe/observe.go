// Package observe holds the scaffolding shared across the per-observer
// packages (internal/observe/<name>): a small generic helper, the live-host
// advisory notes, and the cross-observer confidence utilities the privileged
// composition uses to grade itself as the worse of two observers.
//
// It sits one level above the foundation (it imports internal/sidecar and
// internal/exit) and is imported by the observer subpackages and the CLI. It
// deliberately holds no observer-specific logic — each observer owns its
// event/aggregate/decide/confidence in its own package, per
// docs/organization.md.
package observe

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// InspectDefaultTimeout bounds the `docker inspect` + `docker history`
// round-trip used by the observers that correlate against the container
// runtime (the caps entrypoint cross-check, the fs mount acquisition). The
// cross-check is best-effort and must not stall the pipeline; 10s is generous
// for local-daemon lookups and aggressive for network-pull fallbacks (which
// would fail anyway if the image isn't already local).
const InspectDefaultTimeout = 10 * time.Second

// MaxScanLineBytes caps the size of a single line the observers' bufio.Scanners
// will buffer (the max token size). Every aggregator parses untrusted subprocess
// output — ig gadget NDJSON, `docker history` layers — inside a root-equivalent
// process, so a hostile or corrupt stream could otherwise pack one enormous line
// and drive unbounded allocation. Bounding it at 1 MiB turns that into a
// bufio.ErrTooLong, which each aggregator surfaces via scan.Err() as a hard
// parse failure (the safe direction: refuse, don't silently truncate to a
// smaller cap set). 64 KiB is the initial buffer; the scanner grows to this
// ceiling only on demand, so the common small-line case pays nothing.
const MaxScanLineBytes = 1024 * 1024

// SortedKeys returns the keys of m in ascending order. Observers use it to
// emit deterministic comm-sample / derived-cap / destination slices.
func SortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// EmitAdvisoryWarnings surfaces sub-abort signals the aggregator already
// records but didn't previously make user-visible. PLAN.md §v0.1 build
// order rc bullet 9: replica disagreement and sub-10% drop rate are
// recorded on the sidecar but only useful if reviewers can see them
// without reading the JSON. Both are non-fatal (the ≥10% drop abort
// stays); silent stderr is the cheapest path to making them obvious.
func EmitAdvisoryWarnings(s *sidecar.Sidecar, stderr io.Writer, live bool, container, image string) {
	if stderr == nil {
		return
	}
	// A LIVE run that recorded zero events yields a fully-formed but
	// maximally-restrictive profile (cap_drop: ALL) at exit 0 — and a selector
	// that matched no running container (a typo'd --container, a wrong --image,
	// a window in which the target never ran, or a no-op/broken `ig`) is
	// indistinguishable at the CLI surface from a container observed to
	// genuinely need nothing. Zero events can be legitimate (an idle container),
	// so this is a warning, not a failure; naming the selector lets an operator
	// — or CI grepping stderr — tell the two apart. Fixture replay is skipped: a
	// zero-event fixture is the caller's own test input, not a live miss.
	if live && s.TraceHealth.EventsRecorded == 0 {
		fmt.Fprintf(stderr,
			"csd: warning: 0 events recorded for %s — the profile is the maximally-restrictive default (nothing was observed), not a derived minimum; confirm the selector matched a running container that exercised the workload\n",
			selectorDesc(container, image),
		)
	}
	if s.TraceHealth.DropRate > 0 && s.TraceHealth.DropRate < exit.DropRateAbort {
		fmt.Fprintf(stderr,
			"csd: warning: trace_health drop_rate %.4f (%d dropped / %d recorded); below %.2f abort threshold but profile may be incomplete\n",
			s.TraceHealth.DropRate, s.TraceHealth.EventsDropped, s.TraceHealth.EventsRecorded, exit.DropRateAbort,
		)
	}
	if len(s.Target.ReplicaCapDisagreement) > 0 {
		fmt.Fprintf(stderr,
			"csd: warning: replicas disagree on %d cap(s) [%s]; --all-matching produced a union profile that no single replica required\n",
			len(s.Target.ReplicaCapDisagreement),
			strings.Join(s.Target.ReplicaCapDisagreement, ", "),
		)
	}
	// The privileged decomposition is partial at v0.3 (caps + devices only,
	// not AppArmor/seccomp). Warn on every format — including compose-patch
	// and json, whose output bodies don't carry the `#` caveat comment — so a
	// user never acts on "drop privileged: true" without seeing the gap.
	if s.PrivilegedDecomposition != nil && s.PrivilegedDecomposition.Partial {
		fmt.Fprintf(stderr, "csd: warning: %s\n", s.PrivilegedDecomposition.SecurityOpt)
	}
}

// selectorDesc names the target selector for a warning message: the explicit
// --container / --image the user passed, or a generic fallback.
func selectorDesc(container, image string) string {
	switch {
	case container != "":
		return fmt.Sprintf("--container %q", container)
	case image != "":
		return fmt.Sprintf("--image %q", image)
	default:
		return "the target container"
	}
}

// NoteWSL2IfDetected emits a one-line stderr advisory pointing at
// docs/wsl2.md when the host kernel string identifies as WSL2. PLAN.md
// §Platform support: WSL2 + Docker Desktop is nominally supported but
// kernel coverage and BTF availability vary across builds; the note
// directs the user to the per-image smoke matrix and known-issues list
// before they trust an observation. Live observe path only -- fixture
// replay is host-agnostic.
func NoteWSL2IfDetected(stderr io.Writer) {
	if stderr == nil {
		return
	}
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return
	}
	if !looksLikeWSL2(string(data)) {
		return
	}
	fmt.Fprintln(stderr, "csd: note: WSL2 host detected; see docs/wsl2.md for known-good kernel versions and BTF/Docker Desktop notes")
}

// looksLikeWSL2 returns true when the /proc/version contents match
// either of the two markers WSL2 kernels carry. Both forms have been
// observed across the Microsoft kernel branches: the older lower-case
// "microsoft" tag and the explicit "WSL2" tag on the 5.15+ images.
func looksLikeWSL2(procVersion string) bool {
	lower := strings.ToLower(procVersion)
	return strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl2")
}

// PrefixFactors tags each confidence factor with its source observer, so the
// privileged composition can merge two observers' factors and keep them
// attributable ("[caps] ..." / "[devices] ...").
func PrefixFactors(observer string, factors []string) []string {
	out := make([]string, len(factors))
	for i, f := range factors {
		out[i] = "[" + observer + "] " + f
	}
	return out
}

// ConfidenceRank maps a confidence level to a comparable rank (high=2,
// moderate=1, low/unknown=0).
func ConfidenceRank(level string) int {
	switch level {
	case sidecar.ConfidenceHigh:
		return 2
	case sidecar.ConfidenceModerate:
		return 1
	default:
		return 0
	}
}

// WorseConfidence returns the lower-confidence of a and b. The privileged
// composition grades itself as the worse of the caps and devices observers.
func WorseConfidence(a, b string) string {
	if ConfidenceRank(a) <= ConfidenceRank(b) {
		return a
	}
	return b
}
