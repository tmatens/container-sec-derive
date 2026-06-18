package main

import (
	"os"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

const privCapsFixture = `{"timestamp":1700000005000,"syscall":"socket","cap":"CAP_NET_ADMIN","cap_raw":12,"capable":true,"proc":{"comm":"vpn","pid":5001},"runtime":{"runtimeName":"docker","containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
{"timestamp":1700000007000,"syscall":"ioctl","cap":"CAP_SYS_NICE","cap_raw":23,"capable":true,"proc":{"comm":"renderer","pid":5002},"runtime":{"runtimeName":"docker","containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
`

const privDevFixture = `{"syscall":"openat","flags_raw":2,"fpath":"/dev/dri/card0","proc":{"comm":"renderer"},"runtime":{"containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"/dev/null","proc":{"comm":"renderer"},"runtime":{"containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
{"syscall":"openat","flags_raw":2,"fpath":"/dev/net/tun","proc":{"comm":"vpn"},"runtime":{"containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := t.TempDir() + "/" + name
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProducePrivilegedBothHalves(t *testing.T) {
	caps := writeTemp(t, "caps.ndjson", privCapsFixture)
	dev := writeTemp(t, "dev.ndjson", privDevFixture)
	s, err := producePrivilegedObservation(privilegedPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "gpu-1", InitWindowMs: 0},
		Fixture:       caps,
		DeviceFixture: dev,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pd := s.PrivilegedDecomposition
	if pd == nil || !pd.DropPrivileged {
		t.Fatalf("privileged_decomposition = %+v, want DropPrivileged true", pd)
	}
	if strings.Join(pd.CapAdd, ",") != "NET_ADMIN,SYS_NICE" {
		t.Errorf("cap_add = %v, want [NET_ADMIN SYS_NICE]", pd.CapAdd)
	}
	want := "/dev/dri/card0,/dev/net/tun" // /dev/null excluded
	if strings.Join(pd.Devices, ",") != want {
		t.Errorf("devices = %v, want %s", pd.Devices, want)
	}
	// Both evidence blocks present.
	if len(s.Capabilities) != 2 || s.DeviceRecommendation == nil || len(s.DevicePaths) != 2 {
		t.Errorf("evidence blocks: caps=%d deviceRec=%v devicePaths=%d", len(s.Capabilities), s.DeviceRecommendation, len(s.DevicePaths))
	}
	// trace_health sums both streams: 2 cap events + 2 device events (/dev/null excluded).
	if s.TraceHealth.EventsRecorded != 4 {
		t.Errorf("events_recorded = %d, want 4 (2 caps + 2 devices)", s.TraceHealth.EventsRecorded)
	}
	// Confidence factors are tagged by sub-observer.
	var sawCaps, sawDev bool
	for _, f := range s.Confidence.Factors {
		if strings.HasPrefix(f, "[caps] ") {
			sawCaps = true
		}
		if strings.HasPrefix(f, "[devices] ") {
			sawDev = true
		}
	}
	if !sawCaps || !sawDev {
		t.Errorf("factors should be tagged by both observers: %v", s.Confidence.Factors)
	}
}

func TestProducePrivilegedCapsOnly(t *testing.T) {
	caps := writeTemp(t, "caps.ndjson", privCapsFixture)
	s, err := producePrivilegedObservation(privilegedPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "gpu-1", InitWindowMs: 0},
		Fixture:       caps,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.PrivilegedDecomposition.CapAdd) != 2 {
		t.Errorf("cap_add = %v, want 2", s.PrivilegedDecomposition.CapAdd)
	}
	if len(s.PrivilegedDecomposition.Devices) != 0 {
		t.Errorf("no device fixture → devices should be empty, got %v", s.PrivilegedDecomposition.Devices)
	}
}

func TestWorseConfidence(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{sidecar.ConfidenceHigh, sidecar.ConfidenceLow, sidecar.ConfidenceLow},
		{sidecar.ConfidenceModerate, sidecar.ConfidenceHigh, sidecar.ConfidenceModerate},
		{sidecar.ConfidenceHigh, sidecar.ConfidenceHigh, sidecar.ConfidenceHigh},
		{sidecar.ConfidenceLow, sidecar.ConfidenceModerate, sidecar.ConfidenceLow},
	}
	for _, c := range cases {
		if got := worseConfidence(c.a, c.b); got != c.want {
			t.Errorf("worseConfidence(%s,%s) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}

func TestWritePrivilegedCompose(t *testing.T) {
	s := sidecar.NewSidecar()
	s.Capabilities = []sidecar.Capability{{Name: "SYS_NICE"}}
	s.DeviceRecommendation = &sidecar.DeviceRecommendation{Devices: []string{"/dev/dri/card0"}}
	var b strings.Builder
	if err := writePrivilegedCompose(&b, s); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# privileged: true is not required",
		"cap_drop:",
		"- ALL",
		"cap_add:",
		"- SYS_NICE",
		"devices:",
		"- /dev/dri/card0:/dev/dri/card0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("privileged compose missing %q\n%s", want, out)
		}
	}
}

func TestWritePrivilegedComposeNoDevices(t *testing.T) {
	s := sidecar.NewSidecar()
	s.Capabilities = []sidecar.Capability{{Name: "SYS_NICE"}}
	s.DeviceRecommendation = &sidecar.DeviceRecommendation{}
	var b strings.Builder
	if err := writePrivilegedCompose(&b, s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "no non-default device opens observed") {
		t.Errorf("empty device rec should note no devices:\n%s", b.String())
	}
}
