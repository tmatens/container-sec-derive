package caps

import (
	"fmt"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// ComputeConfidence populates s.Confidence by mechanically applying
// PLAN.md §Confidence scoring to the inputs available on the sidecar.
// The grade must be reproducible from s.Confidence.Factors -- every
// factor that fires is appended verbatim, never per-image-special-cased.
//
// Step 6 implements the deterministic subset of the rubric. Inputs we
// don't yet collect are surfaced as "deferred:" factors and cap the
// achievable level at moderate; later steps wire them in:
//
//   - steady-state detection   -- needs time-windowed aggregation
//   - target exited early      -- needs observe()-side instrumentation
//
// Step 17 wired workload script presence: --workload's path is recorded
// on the sidecar at flag-parse time and read here. PLAN.md §Confidence
// scoring lists "no workload script" as a Moderate condition (not Low),
// so absence contributes one moderate hit rather than forcing the grade.
//
// Step 15 (v0.1.0-rc) wired the entrypoint cross-check as an
// informational factor; Step 32 (v0.1.0-rc, phase B) wires PLAN.md
// §Workload coverage item 2's force-low rule: when the cross-check
// ran and any coverage_warnings fired, confidence is forced to low.
// The phase B decision was made on Step 30 + Step 31 evidence that
// the heuristic table fires zero signals on the reference images
// (postgres argv = `docker-entrypoint.sh postgres`, caddy =
// `caddy run ...`, tailscale = `containerboot`, synthetic =
// `/exerciser` -- none match the chown/chmod/gosu/su-exec/setpriv/
// mount/umount/ping table). Force-low is therefore additive and
// regression-free on current workloads; it locks in the rubric's
// answer to entrypoint-mismatch ahead of any v0.2+ work that
// expands the heuristic (layer-script reading, etc.) to actually
// fire signals.
//
// Reporting deferred factors honestly (rather than silently grading
// High) keeps the rubric trustworthy while the rest of the inputs land.
func ComputeConfidence(s *sidecar.Sidecar) {
	var c observe.ConfidenceBuilder

	// Event count (post-init-filter).
	eventCount := 0
	for _, n := range s.Target.PerReplicaEventCounts {
		eventCount += n
	}
	switch {
	case eventCount < 100:
		c.Low(fmt.Sprintf("event count %d < 100", eventCount))
	case eventCount < 1000:
		c.Moderate(fmt.Sprintf("event count %d in 100-999", eventCount))
	default:
		c.Info(fmt.Sprintf("event count %d >= 1000", eventCount))
	}

	// Drop rate. The runner is meant to abort at >=10%; if a sidecar with
	// that rate still reaches us, surface it as low rather than trust it.
	c.AddDropRateFactors(s.TraceHealth.DropRate)

	// Replica disagreement under --all-matching.
	switch n := len(s.Target.ReplicaCapDisagreement); {
	case n > 1:
		c.Low(fmt.Sprintf("replica cap disagreement spans %d caps: %v", n, s.Target.ReplicaCapDisagreement))
	case n == 1:
		c.Moderate(fmt.Sprintf("replica cap disagreement: %v", s.Target.ReplicaCapDisagreement))
	}

	// Duration soft floor. DurationSeconds == 0 means "not measured"
	// (e.g. fixture mode); only fire the floor when we actually know.
	if s.DurationSeconds > 0 && s.DurationSeconds < 60 {
		c.Low(fmt.Sprintf("observation duration %ds < 60s soft floor", s.DurationSeconds))
	}

	// Comm diversity (post-init-window). Skip when there were no events
	// at all -- the event-count factor already covers that case.
	if eventCount > 0 {
		switch d := s.Target.DistinctComms; {
		case d < 2:
			c.Low(fmt.Sprintf("distinct comms = %d < 2", d))
		case d == 2:
			c.Moderate("distinct comms = 2")
		default:
			c.Info(fmt.Sprintf("distinct comms = %d", d))
		}
	}

	// Workload script presence (PLAN.md §Confidence scoring). Recording
	// the path is enough for the rubric -- the compose-lint contribution
	// gate is the layer that re-checks readability.
	if s.Workload != "" {
		c.Info("workload script provided (" + s.Workload + ")")
	} else {
		c.Moderate("no workload script provided (startup + idle only)")
	}

	// Entrypoint cross-check (PLAN.md §Workload coverage items 1-2).
	// Phase B (Step 32): coverage_warnings non-empty forces low. The
	// populated ExpectedCapsFromEntrypoint + CoverageWarnings fields
	// remain the authoritative record regardless of grade pressure.
	switch {
	case s.CrossCheckStatus == "":
		// Skipped (fixture mode without --inspect-fixture, or no image
		// reference available in a path that didn't attempt inspect).
		// Emit no factor -- absence of evidence isn't evidence of
		// absence, and the sidecar's empty ExpectedCapsFromEntrypoint
		// + empty CoverageWarnings already tell the reviewer.
	case len(s.CoverageWarnings) > 0:
		// Argv-derived coverage warnings force low. Checked before the
		// unavailable/partial branches because the warnings come from the
		// inspect argv, which is present on both a fully-"ok" run and a
		// partial (history-unavailable) one (issue #180) -- so a degraded
		// `history` must not silently drop the force-low signal.
		c.Low(fmt.Sprintf("%d entrypoint coverage warnings present (see coverage_warnings)", len(s.CoverageWarnings)))
	case strings.HasPrefix(s.CrossCheckStatus, sidecar.CrossCheckStatusPartialHistoryPrefix):
		// Inspect half succeeded (argv cross-check + digest authoritative);
		// history half failed, so setcap-from-history signals are absent but
		// no argv warnings fired. Informational, not a grade penalty.
		c.Info("entrypoint cross-check partial: " + strings.TrimPrefix(s.CrossCheckStatus, sidecar.CrossCheckStatusPartialHistoryPrefix))
	case s.CrossCheckStatus != sidecar.CrossCheckStatusOK:
		// Attempted but failed (docker daemon down, image not present,
		// etc.). Informational factor with the truncated reason so the
		// reviewer can see why the check couldn't run.
		c.Info("entrypoint cross-check unavailable: " + s.CrossCheckStatus)
	case len(s.ExpectedCapsFromEntrypoint) == 0:
		c.Info("entrypoint cross-check ran; no static signals matched")
	default:
		c.Info(fmt.Sprintf("entrypoint cross-check clean (%d expected caps covered)", len(s.ExpectedCapsFromEntrypoint)))
	}

	// Deferred preconditions for High. These cap the achievable grade at
	// moderate until later steps wire in the inputs.
	c.Factors = append(c.Factors,
		"deferred: steady-state detection not yet implemented",
		"deferred: target-exited-early signal not yet wired",
	)

	s.Confidence.Factors = c.Factors
	switch {
	case c.ForceLow, c.ModerateHits >= 2:
		s.Confidence.Level = sidecar.ConfidenceLow
	default:
		// Capped at moderate while deferred preconditions stand.
		s.Confidence.Level = sidecar.ConfidenceModerate
	}
}
