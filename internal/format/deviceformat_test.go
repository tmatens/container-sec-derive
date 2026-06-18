package format

import (
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestWriteDeviceCompose(t *testing.T) {
	var b strings.Builder
	rec := sidecar.DeviceRecommendation{
		Devices:     []string{"/dev/dri/card0", "/dev/net/tun"},
		DerivedCaps: []string{"CAP_NET_ADMIN"},
	}
	if err := WriteDeviceCompose(&b, rec); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"devices:",
		"  - /dev/dri/card0:/dev/dri/card0",
		"  - /dev/net/tun:/dev/net/tun",
		"# note:", "CAP_NET_ADMIN",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compose output missing %q\n%s", want, out)
		}
	}
}

func TestWriteDeviceComposeEmpty(t *testing.T) {
	var b strings.Builder
	if err := WriteDeviceCompose(&b, sidecar.DeviceRecommendation{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.HasPrefix(out, "# no non-default device opens observed") {
		t.Errorf("empty recommendation should emit the no-devices comment, got:\n%s", out)
	}
	if strings.Contains(out, "\n  - ") || strings.HasPrefix(out, "devices:") {
		t.Errorf("empty recommendation must not emit a devices: block or entries:\n%s", out)
	}
}
