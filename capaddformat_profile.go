package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// writeCapaddComposeLintProfile emits a YAML entry for contributing a v0.5
// dangerous-cap_add validation to the compose-lint catalog — the CL-0011 analog
// of writeComposeLintProfile (CL-0006) and the device/fs profiles. Same
// acceptance-contract enforcement and --allow-exploratory escape hatch; the body
// carries the recommended minimized cap_add and the validated caps. The
// `observer: capadd` line distinguishes it from a capability-derivation entry for
// the same image.
//
// Contract (capadd variant): the shared gate (schema within 1.x, image_digest,
// workload readable, duration_seconds >= 300, confidence high/moderate,
// drop_rate < 1%, replica_cap_disagreement empty) PLUS granted_set_provided —
// without the granted set there is no minimized cap_add to contribute, so an
// unscoped capadd run cannot clear the CL-0011 contribution bar.
func writeCapaddComposeLintProfile(w io.Writer, s *Sidecar, allowExploratory bool) error {
	violations := checkCapaddComposeLintContract(s)
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

	val := s.CapaddValidation
	if val == nil {
		val = &capaddValidation{Findings: []CapaddFinding{}, RecommendedCapAdd: []string{}}
	}
	if _, err := fmt.Fprintf(w, "%srecommended_cap_add: [%s]\n", bodyIndent, strings.Join(val.RecommendedCapAdd, ", ")); err != nil {
		return err
	}
	var validated []string
	for _, f := range val.Findings {
		if f.Used {
			validated = append(validated, f.Cap)
		}
	}
	if _, err := fmt.Fprintf(w, "%svalidated_caps: [%s]\n", bodyIndent, strings.Join(validated, ", ")); err != nil {
		return err
	}

	fmt.Fprintf(w, "%sderivation:\n", bodyIndent)
	fmt.Fprintf(w, "%s  tool: container-sec-derive\n", bodyIndent)
	fmt.Fprintf(w, "%s  observer: capadd\n", bodyIndent)
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

// checkCapaddComposeLintContract returns the capadd acceptance-contract
// violations in a fixed order (the same deterministic-diagnostic requirement as
// the cap/fs/device contracts). Empty slice means the sidecar clears the gate.
func checkCapaddComposeLintContract(s *Sidecar) []string {
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
	if s.TraceHealth.DropRate >= ComposeLintMaxDropRate {
		v = append(v, fmt.Sprintf("trace_health.drop_rate %.4f >= %.2f", s.TraceHealth.DropRate, ComposeLintMaxDropRate))
	}
	if len(s.Target.ReplicaCapDisagreement) > 0 {
		v = append(v, fmt.Sprintf("replica_cap_disagreement non-empty (%d cap(s) disagree across replicas)", len(s.Target.ReplicaCapDisagreement)))
	}
	if s.CapaddValidation == nil || !s.CapaddValidation.GrantedSetProvided {
		v = append(v, "granted set not provided (--cap-add); no minimized cap_add to contribute")
	}
	return v
}
