package devices

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/obstest"
)

// TestObserveDevices_FakeIG is TG3 for the device observer's live path (also 0%
// before): a fake ig streams trace_open device events + a loss line.
func TestObserveDevices_FakeIG(t *testing.T) {
	nd := strings.Join([]string{
		`{"syscall":"openat","flags_raw":2,"fpath":"/dev/kvm","proc":{"comm":"q"},"runtime":{"containerId":"c1","containerName":"vm","containerImageName":"vm:1"}}`,
		`{"syscall":"openat","flags_raw":2,"fpath":"/dev/null","proc":{"comm":"q"},"runtime":{"containerId":"c1","containerName":"vm","containerImageName":"vm:1"}}`,
	}, "\n")
	ig := obstest.FakeIGRun(t, nd, "lost 2 samples\n")

	obs, err := ObserveDevices(context.Background(), ig, attrib.Opts{}, io.Discard)
	if err != nil {
		t.Fatalf("observeDevices: %v", err)
	}
	// /dev/null is a default device node (excluded); /dev/kvm is a real grant.
	if len(obs.Devices) != 1 || obs.Devices[0] != "/dev/kvm" {
		t.Errorf("Devices = %v, want [/dev/kvm]", obs.Devices)
	}
	if obs.Dropped != 2 {
		t.Errorf("Dropped = %d, want 2", obs.Dropped)
	}
}
