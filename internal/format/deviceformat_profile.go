package format

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// WriteDeviceComposeLintProfile emits a YAML entry for contributing a v0.3
// device-decomposition profile to the compose-lint catalog — the CL-0002 analog
// of WriteComposeLintProfile (CL-0006) and WriteFSComposeLintProfile (CL-0007).
// Same acceptance-contract enforcement and --allow-exploratory escape hatch; the
// body carries the observed `devices:` (and any derived-cap hints) instead of
// caps or read_only/tmpfs. The `observer: devices` line under derivation
// distinguishes it from a capability or fs entry for the same image.
//
// Contract (device variant of CheckComposeLintContract): schema_version within
// 1.x, image_digest present, workload readable, duration_seconds >= 300,
// confidence high/moderate, trace_health.drop_rate < 1%, and
// replica_device_disagreement empty (the device analog of the cap/fs
// disagreement gate). coverage_warnings is not checked — it is the cap
// entrypoint-cross-check signal and is always empty on a device run.
func WriteDeviceComposeLintProfile(w io.Writer, s *sidecar.Sidecar, allowExploratory bool) error {
	violations := CheckDeviceComposeLintContract(s)
	if len(violations) > 0 && !allowExploratory {
		return composeLintContractError(violations)
	}
	rec := s.DeviceRecommendation
	if rec == nil {
		rec = &sidecar.DeviceRecommendation{}
	}
	return writeComposeLintAggregate(w, s, "devices", "devices", violations,
		func(sw *stickyWriter, ind string) {
			// devices + derived_caps as flow-style sequences to match the
			// caps/fs entries' compact shape; both are already sorted by the
			// decision layer.
			sw.printf("%sdevices: [%s]\n", ind, strings.Join(rec.Devices, ", "))
			sw.printf("%sderived_caps: [%s]\n", ind, strings.Join(rec.DerivedCaps, ", "))
		})
}

// CheckDeviceComposeLintContract returns the device acceptance-contract
// violations in a fixed order (the same deterministic-diagnostic requirement as
// the cap/fs contracts). Empty slice means the sidecar clears the gate.
func CheckDeviceComposeLintContract(s *sidecar.Sidecar) []string {
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
	if len(s.Target.ReplicaDeviceDisagreement) > 0 {
		v = append(v, fmt.Sprintf("replica_device_disagreement non-empty (%d nodes disagree across replicas)", len(s.Target.ReplicaDeviceDisagreement)))
	}
	return v
}
