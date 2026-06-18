package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// writeFSComposeLintProfile emits a YAML entry for contributing a v0.2
// read-only-filesystem profile to the compose-lint catalog — the CL-0007
// analog of writeComposeLintProfile (CL-0006). Same acceptance-contract
// enforcement and --allow-exploratory escape hatch; the body carries
// read_only/tmpfs instead of caps. The `observer: fs` line under derivation
// distinguishes it from a capability entry for the same image.
//
// Contract (fs variant of checkComposeLintContract): schema_version within
// 1.x, image_digest present, workload readable, duration_seconds >= 300,
// confidence high/moderate, trace_health.drop_rate < 1%, and
// replica_write_path_disagreement empty (the fs analog of the cap
// disagreement gate). coverage_warnings is not checked — it is the cap
// entrypoint-cross-check signal and is always empty on an fs run.
func writeFSComposeLintProfile(w io.Writer, s *sidecar.Sidecar, allowExploratory bool) error {
	violations := checkFSComposeLintContract(s)
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

	rec := s.FSRecommendation
	if rec == nil {
		rec = &sidecar.FSRecommendation{ReadOnly: true}
	}
	if _, err := fmt.Fprintf(w, "%sread_only: %t\n", bodyIndent, rec.ReadOnly); err != nil {
		return err
	}
	// tmpfs as a flow-style sequence to match the caps entry's compact shape;
	// paths are already sorted by the decision layer.
	if _, err := fmt.Fprintf(w, "%stmpfs: [%s]\n", bodyIndent, strings.Join(rec.TmpfsPaths, ", ")); err != nil {
		return err
	}

	fmt.Fprintf(w, "%sderivation:\n", bodyIndent)
	fmt.Fprintf(w, "%s  tool: container-sec-derive\n", bodyIndent)
	fmt.Fprintf(w, "%s  observer: fs\n", bodyIndent)
	fmt.Fprintf(w, "%s  tool_version: %s\n", bodyIndent, s.ToolVersion)
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

// checkFSComposeLintContract returns the fs acceptance-contract violations in
// a fixed order (the same deterministic-diagnostic requirement as the cap
// contract). Empty slice means the sidecar clears the gate.
func checkFSComposeLintContract(s *sidecar.Sidecar) []string {
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
	case sidecar.ConfidenceHigh, sidecar.ConfidenceModerate:
		// ok
	case "":
		v = append(v, "confidence.level not set")
	default:
		v = append(v, fmt.Sprintf("confidence.level %q below moderate (see confidence.factors)", s.Confidence.Level))
	}
	if s.TraceHealth.DropRate >= ComposeLintMaxDropRate {
		v = append(v, fmt.Sprintf("trace_health.drop_rate %.4f >= %.2f", s.TraceHealth.DropRate, ComposeLintMaxDropRate))
	}
	if len(s.Target.ReplicaWritePathDisagreement) > 0 {
		v = append(v, fmt.Sprintf("replica_write_path_disagreement non-empty (%d paths disagree across replicas)", len(s.Target.ReplicaWritePathDisagreement)))
	}
	return v
}
