package privileged

import (
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/obstest"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestProducePrivilegedBothHalves(t *testing.T) {
	caps := obstest.WriteTemp(t, "caps.ndjson", obstest.PrivCapsFixture)
	dev := obstest.WriteTemp(t, "dev.ndjson", obstest.PrivDevFixture)
	s, err := ProducePrivilegedObservation(PrivilegedPipelineOpts{
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
	caps := obstest.WriteTemp(t, "caps.ndjson", obstest.PrivCapsFixture)
	s, err := ProducePrivilegedObservation(PrivilegedPipelineOpts{
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
		if got := observe.WorseConfidence(c.a, c.b); got != c.want {
			t.Errorf("worseConfidence(%s,%s) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}
