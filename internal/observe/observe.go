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
func EmitAdvisoryWarnings(s *sidecar.Sidecar, stderr io.Writer) {
	if stderr == nil {
		return
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
