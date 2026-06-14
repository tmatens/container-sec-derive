package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// writeDeviceComposeLintProfile emits a YAML entry for contributing a v0.3
// device-decomposition profile to the compose-lint catalog — the CL-0002 analog
// of writeComposeLintProfile (CL-0006) and writeFSComposeLintProfile (CL-0007).
// Same acceptance-contract enforcement and --allow-exploratory escape hatch; the
// body carries the observed `devices:` (and any derived-cap hints) instead of
// caps or read_only/tmpfs. The `observer: devices` line under derivation
// distinguishes it from a capability or fs entry for the same image.
//
// Contract (device variant of checkComposeLintContract): schema_version within
// 1.x, image_digest present, workload readable, duration_seconds >= 300,
// confidence high/moderate, trace_health.drop_rate < 1%, and
// replica_device_disagreement empty (the device analog of the cap/fs
// disagreement gate). coverage_warnings is not checked — it is the cap
// entrypoint-cross-check signal and is always empty on a device run.
func writeDeviceComposeLintProfile(w io.Writer, s *Sidecar, allowExploratory bool) error {
	violations := checkDeviceComposeLintContract(s)
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

	rec := s.DeviceRecommendation
	if rec == nil {
		rec = &deviceRecommendation{}
	}
	// devices + derived_caps as flow-style sequences to match the caps/fs
	// entries' compact shape; both are already sorted by the decision layer.
	if _, err := fmt.Fprintf(w, "%sdevices: [%s]\n", bodyIndent, strings.Join(rec.Devices, ", ")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%sderived_caps: [%s]\n", bodyIndent, strings.Join(rec.DerivedCaps, ", ")); err != nil {
		return err
	}

	fmt.Fprintf(w, "%sderivation:\n", bodyIndent)
	fmt.Fprintf(w, "%s  tool: container-sec-derive\n", bodyIndent)
	fmt.Fprintf(w, "%s  observer: devices\n", bodyIndent)
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

// checkDeviceComposeLintContract returns the device acceptance-contract
// violations in a fixed order (the same deterministic-diagnostic requirement as
// the cap/fs contracts). Empty slice means the sidecar clears the gate.
func checkDeviceComposeLintContract(s *Sidecar) []string {
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
	if len(s.Target.ReplicaDeviceDisagreement) > 0 {
		v = append(v, fmt.Sprintf("replica_device_disagreement non-empty (%d nodes disagree across replicas)", len(s.Target.ReplicaDeviceDisagreement)))
	}
	return v
}
