package devices

import (
	"os"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/obstest"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// TestProduceDeviceObservationFixture exercises the fixture path end-to-end:
// aggregate → deviceToSidecar → ComputeDeviceConfidence, and asserts the device
// section is populated while the cap/fs scaffolding stays empty (one observer
// per run).
func TestProduceDeviceObservationFixture(t *testing.T) {
	dir := t.TempDir()
	fix := dir + "/dev.ndjson"
	const nd = `{"syscall":"openat","flags_raw":2,"fpath":"/dev/dri/card0","proc":{"comm":"r"},"runtime":{"containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"/dev/null","proc":{"comm":"r"},"runtime":{"containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
{"syscall":"openat","flags_raw":2,"fpath":"/dev/net/tun","proc":{"comm":"v"},"runtime":{"containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
`
	if err := os.WriteFile(fix, []byte(nd), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := ProduceDeviceObservation(DevicePipelineOpts{
		AggregateOpts: attrib.Opts{Container: "gpu-1"},
		Fixture:       fix,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != "1.6" || s.ToolVersion != "0.7.0" {
		t.Errorf("version = %s / %s, want 1.6 / 0.7.0", s.SchemaVersion, s.ToolVersion)
	}
	if s.DeviceRecommendation == nil {
		t.Fatal("device recommendation is nil")
	}
	want := []string{"/dev/dri/card0", "/dev/net/tun"} // /dev/null excluded
	if strings.Join(s.DeviceRecommendation.Devices, ",") != strings.Join(want, ",") {
		t.Errorf("devices = %v, want %v", s.DeviceRecommendation.Devices, want)
	}
	if strings.Join(s.DeviceRecommendation.DerivedCaps, ",") != "CAP_NET_ADMIN" {
		t.Errorf("derived caps = %v, want [CAP_NET_ADMIN]", s.DeviceRecommendation.DerivedCaps)
	}
	if len(s.DevicePaths) != 2 {
		t.Errorf("device_paths = %d entries, want 2", len(s.DevicePaths))
	}
	// One observer per run: cap + fs scaffolding stays empty.
	if len(s.Capabilities) != 0 || s.FSRecommendation != nil || len(s.WritablePaths) != 0 {
		t.Errorf("device run leaked cap/fs fields: caps=%d fs=%v writable=%d",
			len(s.Capabilities), s.FSRecommendation, len(s.WritablePaths))
	}
	if s.TraceHealth.EventsRecorded != 2 {
		t.Errorf("events recorded = %d, want 2", s.TraceHealth.EventsRecorded)
	}
}

func TestComputeDeviceConfidence(t *testing.T) {
	// No workload + nothing else wrong → exactly one moderate hit → moderate.
	s := sidecar.NewSidecar()
	s.DevicePaths = []sidecar.DevicePath{{Path: "/dev/kvm", EventCount: 1}}
	s.TraceHealth.EventsRecorded = 1
	ComputeDeviceConfidence(s)
	if s.Confidence.Level != sidecar.ConfidenceModerate {
		t.Errorf("sparse-but-clean device run = %q, want moderate (no event-count floor)", s.Confidence.Level)
	}

	// A drop rate >= 1% forces low regardless of how many devices were seen.
	s2 := sidecar.NewSidecar()
	s2.Workload = "/w.sh"
	s2.DevicePaths = []sidecar.DevicePath{{Path: "/dev/kvm"}}
	s2.TraceHealth.DropRate = 0.02
	ComputeDeviceConfidence(s2)
	if s2.Confidence.Level != sidecar.ConfidenceLow {
		t.Errorf("drop-rate 2%% device run = %q, want low", s2.Confidence.Level)
	}

	// Empty observation (no non-default devices) is a clean, valid result, not
	// a low-confidence one: with a workload it stays moderate.
	s3 := sidecar.NewSidecar()
	s3.Workload = "/w.sh"
	ComputeDeviceConfidence(s3)
	if s3.Confidence.Level != sidecar.ConfidenceModerate {
		t.Errorf("empty device observation = %q, want moderate", s3.Confidence.Level)
	}
	if !obstest.ContainsSubstr(s3.Confidence.Factors, "no non-default device opens observed") {
		t.Errorf("empty observation should note no devices: %v", s3.Confidence.Factors)
	}
}
