package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteDeviceDockerRun(t *testing.T) {
	var b strings.Builder
	rec := deviceRecommendation{Devices: []string{"/dev/dri/card0", "/dev/net/tun"}, DerivedCaps: []string{"CAP_NET_ADMIN"}}
	if err := writeDeviceDockerRun(&b, rec); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "--device /dev/dri/card0:/dev/dri/card0 --device /dev/net/tun:/dev/net/tun") {
		t.Errorf("missing --device flags:\n%s", out)
	}
	if !strings.Contains(out, "--cap-add CAP_NET_ADMIN") {
		t.Errorf("missing derived-cap note:\n%s", out)
	}

	var e strings.Builder
	if err := writeDeviceDockerRun(&e, deviceRecommendation{}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(e.String(), "# no non-default device") {
		t.Errorf("empty should emit the no-devices comment: %q", e.String())
	}
}

func TestWriteDeviceK8s(t *testing.T) {
	var b strings.Builder
	if err := writeDeviceK8s(&b, deviceRecommendation{Devices: []string{"/dev/dri/card0"}}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"#   - /dev/dri/card0", "device-plugin", "securityContext:", "  privileged: false"} {
		if !strings.Contains(out, want) {
			t.Errorf("k8s output missing %q\n%s", want, out)
		}
	}
}

func TestWriteDeviceOCIValidJSONAnnotations(t *testing.T) {
	var b strings.Builder
	rec := deviceRecommendation{Devices: []string{"/dev/dri/card0", "/dev/net/tun"}, DerivedCaps: []string{"CAP_NET_ADMIN"}}
	if err := writeDeviceOCI(&b, rec); err != nil {
		t.Fatal(err)
	}
	// Must be valid JSON (it's an OCI config.json fragment).
	var parsed struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal([]byte(b.String()), &parsed); err != nil {
		t.Fatalf("oci output is not valid JSON: %v\n%s", err, b.String())
	}
	if parsed.Annotations["org.containersecderive.observed-devices"] != "/dev/dri/card0,/dev/net/tun" {
		t.Errorf("observed-devices annotation = %q", parsed.Annotations["org.containersecderive.observed-devices"])
	}
	if !strings.Contains(parsed.Annotations["org.containersecderive.devices-note"], "major/minor") {
		t.Errorf("note should explain major/minor resolution: %q", parsed.Annotations["org.containersecderive.devices-note"])
	}
	if parsed.Annotations["org.containersecderive.derived-caps"] != "CAP_NET_ADMIN" {
		t.Errorf("derived-caps annotation = %q", parsed.Annotations["org.containersecderive.derived-caps"])
	}
}
