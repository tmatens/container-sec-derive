package devices

import (
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/obstest"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// TestDeviceMultiReplicaDisagreement: under --all-matching, a device node
// observed on only one of two replicas must surface in
// ReplicaDeviceDisagreement and drop confidence accordingly.
func TestDeviceMultiReplicaDisagreement(t *testing.T) {
	// Both replicas open /dev/kvm; only vm-2 opens /dev/net/tun.
	const nd = `
{"syscall":"openat","flags_raw":2,"fpath":"/dev/kvm","proc":{"comm":"q"},"runtime":{"containerId":"aaa111aaa111","containerName":"vm-1","containerImageName":"vm:1"}}
{"syscall":"openat","flags_raw":2,"fpath":"/dev/kvm","proc":{"comm":"q"},"runtime":{"containerId":"bbb222bbb222","containerName":"vm-2","containerImageName":"vm:1"}}
{"syscall":"openat","flags_raw":2,"fpath":"/dev/net/tun","proc":{"comm":"q"},"runtime":{"containerId":"bbb222bbb222","containerName":"vm-2","containerImageName":"vm:1"}}
`
	obs, err := AggregateDevices(strings.NewReader(nd), attrib.Opts{Image: "vm:1", AllMatching: true})
	if err != nil {
		t.Fatal(err)
	}
	s := deviceToSidecar(obs, attrib.Opts{Image: "vm:1", AllMatching: true})
	if len(s.Target.ReplicaDeviceDisagreement) != 1 || s.Target.ReplicaDeviceDisagreement[0] != "/dev/net/tun" {
		t.Fatalf("disagreement = %v, want [/dev/net/tun]", s.Target.ReplicaDeviceDisagreement)
	}
	// The union recommendation still includes both devices.
	if len(s.DeviceRecommendation.Devices) != 2 {
		t.Errorf("union devices = %v, want 2", s.DeviceRecommendation.Devices)
	}

	// One-node disagreement is a single moderate factor; with no workload that's
	// a second moderate → low.
	ComputeDeviceConfidence(s)
	if s.Confidence.Level != sidecar.ConfidenceLow {
		t.Errorf("confidence = %q, want low (disagreement + no-workload = 2 moderates)", s.Confidence.Level)
	}
	if !obstest.ContainsSubstr(s.Confidence.Factors, "replica device disagreement") {
		t.Errorf("disagreement factor missing: %v", s.Confidence.Factors)
	}
}

// Single-replica device runs must leave ReplicaDeviceDisagreement empty (the
// field is only meaningful with >1 replica).
func TestDeviceSingleReplicaNoDisagreement(t *testing.T) {
	const nd = `{"syscall":"openat","flags_raw":2,"fpath":"/dev/kvm","proc":{"comm":"q"},"runtime":{"containerId":"aaa111aaa111","containerName":"vm-1","containerImageName":"vm:1"}}`
	obs, err := AggregateDevices(strings.NewReader(nd), attrib.Opts{Container: "vm-1"})
	if err != nil {
		t.Fatal(err)
	}
	s := deviceToSidecar(obs, attrib.Opts{Container: "vm-1"})
	if s.Target.ReplicaDeviceDisagreement != nil {
		t.Errorf("single replica should have nil disagreement, got %v", s.Target.ReplicaDeviceDisagreement)
	}
}
