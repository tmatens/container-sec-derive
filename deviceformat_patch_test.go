package main

import (
	"strings"
	"testing"
)

func TestWriteDeviceComposePatchInsert(t *testing.T) {
	const in = "services:\n  gpu:\n    image: gpu:1\n"
	var b strings.Builder
	rec := deviceRecommendation{Devices: []string{"/dev/dri/card0", "/dev/net/tun"}}
	if err := writeDeviceComposePatch(&b, rec, []byte(in), "compose.yml", "gpu"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"@@", "+    devices:", "+      - /dev/dri/card0:/dev/dri/card0", "+      - /dev/net/tun:/dev/net/tun"} {
		if !strings.Contains(out, want) {
			t.Errorf("patch missing %q\n%s", want, out)
		}
	}
}

func TestWriteDeviceComposePatchReplace(t *testing.T) {
	const in = "services:\n  gpu:\n    image: gpu:1\n    devices:\n      - /dev/old:/dev/old\n"
	var b strings.Builder
	rec := deviceRecommendation{Devices: []string{"/dev/kvm"}}
	if err := writeDeviceComposePatch(&b, rec, []byte(in), "compose.yml", "gpu"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "-      - /dev/old:/dev/old") || !strings.Contains(out, "+      - /dev/kvm:/dev/kvm") {
		t.Errorf("replace patch wrong:\n%s", out)
	}
}

func TestWriteDeviceComposePatchEmptyNoChange(t *testing.T) {
	// No devices observed → no diff, and crucially no proposal to delete the
	// user's existing devices: block (issue #92 foot-gun).
	const in = "services:\n  gpu:\n    image: gpu:1\n    devices:\n      - /dev/keep:/dev/keep\n"
	var b strings.Builder
	if err := writeDeviceComposePatch(&b, deviceRecommendation{}, []byte(in), "compose.yml", "gpu"); err != nil {
		t.Fatal(err)
	}
	if b.String() != "" {
		t.Errorf("empty recommendation must produce no diff, got:\n%s", b.String())
	}
}

func TestWriteDeviceComposePatchMissingService(t *testing.T) {
	rec := deviceRecommendation{Devices: []string{"/dev/kvm"}}
	if err := writeDeviceComposePatch(nil, rec, []byte("services:\n  other:\n    image: x\n"), "compose.yml", "gpu"); err == nil {
		t.Fatal("expected error for service not found")
	}
}
