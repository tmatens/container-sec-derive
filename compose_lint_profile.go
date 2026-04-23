package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// writeComposeLintProfile emits a YAML entry for contribution to the
// compose-lint catalog (PLAN.md §Contribution loop with compose-lint).
// The formatter is the acceptance-contract enforcer: it refuses to emit
// unless every term below is met. When allowExploratory is true, a
// failing sidecar is still emitted under an `exploratory:` top-level
// key with an `acceptance_contract_violations:` annotation, so the
// receiving catalog's exploratory/ path can surface the gaps without
// pretending the profile is validated.
//
// Contract (PLAN.md §Contribution loop with compose-lint, Decisions 9):
//   - schema_version set and within the current major (1.x)
//   - image_digest present
//   - workload file path set and readable at emit time
//   - duration_seconds >= 300
//   - confidence.level is high or moderate
//   - coverage_warnings empty
//   - trace_health.drop_rate < 1%
//   - replica_cap_disagreement empty
//
// validated_via lists only `bpf-observation` here; the receiving-side
// CI pipeline appends `ci-smoke` once the profile passes the smoke
// gate, per PLAN.md's two-source convention. Emitting both from csd
// would overclaim -- we didn't run that CI.
func writeComposeLintProfile(w io.Writer, s *Sidecar, allowExploratory bool) error {
	violations := checkComposeLintContract(s)
	if len(violations) > 0 && !allowExploratory {
		return fmt.Errorf("compose-lint-profile acceptance contract not met; pass --allow-exploratory to emit anyway:\n  - %s",
			strings.Join(violations, "\n  - "))
	}

	exploratory := len(violations) > 0
	keyIndent := ""
	bodyIndent := "  "
	if exploratory {
		if _, err := fmt.Fprintln(w, "exploratory:"); err != nil {
			return err
		}
		keyIndent = "  "
		bodyIndent = "    "
	}

	key := composeLintKey(s)
	if _, err := fmt.Fprintf(w, "%s%s:\n", keyIndent, key); err != nil {
		return err
	}

	// caps: flow-style single line because compose-lint's cap_profiles.yml
	// uses that shape. Names are already sorted by the aggregator.
	caps := s.CapNames()
	if _, err := fmt.Fprintf(w, "%scaps: [%s]\n", bodyIndent, strings.Join(caps, ", ")); err != nil {
		return err
	}

	fmt.Fprintf(w, "%sderivation:\n", bodyIndent)
	fmt.Fprintf(w, "%s  tool: container-sec-derive\n", bodyIndent)
	fmt.Fprintf(w, "%s  tool_version: %s\n", bodyIndent, s.ToolVersion)
	// schema_version is quoted because "1.0" is a YAML float otherwise and
	// would round-trip as 1 through a naive YAML parser.
	fmt.Fprintf(w, "%s  schema_version: %q\n", bodyIndent, s.SchemaVersion)
	fmt.Fprintf(w, "%s  duration_seconds: %d\n", bodyIndent, s.DurationSeconds)
	fmt.Fprintf(w, "%s  workload: %s\n", bodyIndent, s.Workload)
	fmt.Fprintf(w, "%s  confidence: %s\n", bodyIndent, s.Confidence.Level)

	validatedImage := s.Image
	if s.ImageDigest != "" {
		validatedImage = s.Image + "@" + s.ImageDigest
	}
	fmt.Fprintf(w, "%svalidated_image: %s\n", bodyIndent, validatedImage)
	fmt.Fprintf(w, "%svalidated_date: %s\n", bodyIndent, s.ObservedAt.UTC().Format("2006-01-02"))
	fmt.Fprintf(w, "%svalidated_via: [bpf-observation]\n", bodyIndent)

	if exploratory {
		fmt.Fprintf(w, "%sacceptance_contract_violations:\n", bodyIndent)
		for _, v := range violations {
			fmt.Fprintf(w, "%s  - %s\n", bodyIndent, v)
		}
	}
	return nil
}

// ComposeLintMinDurationSeconds is PLAN.md's 5-minute floor for a
// contributable profile. Shorter windows don't carry enough exercise
// coverage to justify a catalog entry.
const ComposeLintMinDurationSeconds = 300

// ComposeLintMaxDropRate mirrors PLAN.md's <1% drop-rate bar for the
// contribution gate. This is strictly below the confidence rubric's
// 1% downgrade threshold -- the same number, but the formatter enforces
// it independently so a rubric change doesn't silently loosen the gate.
const ComposeLintMaxDropRate = 0.01

// checkComposeLintContract returns the acceptance-contract violations in
// a fixed check order. Empty slice means the sidecar clears the gate.
// Order matters: the output is the user-facing diagnostic and also
// becomes the exploratory-mode annotation, so it must be deterministic.
func checkComposeLintContract(s *Sidecar) []string {
	var v []string
	switch {
	case s.SchemaVersion == "":
		v = append(v, "schema_version missing")
	case !strings.HasPrefix(s.SchemaVersion, "1."):
		v = append(v, fmt.Sprintf("schema_version %q outside current major (1.x)", s.SchemaVersion))
	}
	if s.ImageDigest == "" {
		v = append(v, "image_digest missing (profile cannot be pinned to a digest)")
	}
	switch {
	case s.Workload == "":
		v = append(v, "workload path not set")
	default:
		if _, err := os.Stat(s.Workload); err != nil {
			v = append(v, fmt.Sprintf("workload file %q not readable: %v", s.Workload, err))
		}
	}
	if s.DurationSeconds < ComposeLintMinDurationSeconds {
		v = append(v, fmt.Sprintf("duration_seconds %d < %d", s.DurationSeconds, ComposeLintMinDurationSeconds))
	}
	switch s.Confidence.Level {
	case ConfidenceHigh, ConfidenceModerate:
		// ok
	case "":
		v = append(v, "confidence.level not set")
	default:
		v = append(v, fmt.Sprintf("confidence.level %q below moderate (see confidence.factors)", s.Confidence.Level))
	}
	if len(s.CoverageWarnings) > 0 {
		v = append(v, fmt.Sprintf("coverage_warnings non-empty (%d entries; entrypoint-expected caps not covered)", len(s.CoverageWarnings)))
	}
	if s.TraceHealth.DropRate >= ComposeLintMaxDropRate {
		v = append(v, fmt.Sprintf("trace_health.drop_rate %.4f >= %.2f", s.TraceHealth.DropRate, ComposeLintMaxDropRate))
	}
	if len(s.Target.ReplicaCapDisagreement) > 0 {
		v = append(v, fmt.Sprintf("replica_cap_disagreement non-empty (%d caps disagree across replicas)", len(s.Target.ReplicaCapDisagreement)))
	}
	return v
}

// composeLintKey derives the YAML top-level key from the image ref. The
// compose-lint cap_profiles.yml convention is a short name ("postgres",
// "caddy") rather than the full reference. Strip registry, namespace,
// digest, and tag to land on that shape. Empty image ref falls back to
// "unknown" -- the profile can still be edited by hand before landing
// in a PR; refusing to emit here would hide the violation output.
func composeLintKey(s *Sidecar) string {
	ref := s.Image
	if ref == "" {
		return "unknown"
	}
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	if col := strings.LastIndex(ref, ":"); col >= 0 {
		ref = ref[:col]
	}
	parts := strings.Split(ref, "/")
	out := parts[len(parts)-1]
	if out == "" {
		return "unknown"
	}
	return out
}
