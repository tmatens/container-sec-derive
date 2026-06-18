package format

import (
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestWritePrivilegedCompose(t *testing.T) {
	s := sidecar.NewSidecar()
	s.Capabilities = []sidecar.Capability{{Name: "SYS_NICE"}}
	s.DeviceRecommendation = &sidecar.DeviceRecommendation{Devices: []string{"/dev/dri/card0"}}
	var b strings.Builder
	if err := WritePrivilegedCompose(&b, s); err != nil {
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
	if err := WritePrivilegedCompose(&b, s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "no non-default device opens observed") {
		t.Errorf("empty device rec should note no devices:\n%s", b.String())
	}
}
