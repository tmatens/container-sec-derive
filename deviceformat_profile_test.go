package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// fullyValidDeviceSidecar returns a device sidecar that clears the
// compose-lint acceptance contract, given a readable workload path.
func fullyValidDeviceSidecar(workload string) *sidecar.Sidecar {
	s := sidecar.NewSidecar()
	s.Image = "gpu"
	s.ImageDigest = "sha256:deadbeef"
	s.DurationSeconds = 600
	s.Workload = workload
	s.ObservedAt = time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	s.Confidence.Level = sidecar.ConfidenceModerate
	s.DeviceRecommendation = &sidecar.DeviceRecommendation{
		Devices:     []string{"/dev/dri/card0", "/dev/net/tun"},
		DerivedCaps: []string{"CAP_NET_ADMIN"},
	}
	return s
}

func TestWriteDeviceComposeLintProfileAccepted(t *testing.T) {
	wl := t.TempDir() + "/w.sh"
	if err := os.WriteFile(wl, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := fullyValidDeviceSidecar(wl)
	var b strings.Builder
	if err := writeDeviceComposeLintProfile(&b, s, false); err != nil {
		t.Fatalf("contract should pass: %v", err)
	}
	out := b.String()
	for _, want := range []string{
		"gpu:",
		"devices: [/dev/dri/card0, /dev/net/tun]",
		"derived_caps: [CAP_NET_ADMIN]",
		"observer: devices",
		`schema_version: "1.4"`,
		"confidence: moderate",
		"validated_image: gpu@sha256:deadbeef",
		"validated_via: [bpf-observation]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("profile missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "exploratory:") {
		t.Errorf("accepted profile must not be wrapped in exploratory:\n%s", out)
	}
}

func TestWriteDeviceComposeLintProfileContractGate(t *testing.T) {
	// A sidecar missing digest/workload/duration fails the contract without
	// --allow-exploratory, and the violations are reported.
	s := sidecar.NewSidecar()
	s.Image = "gpu"
	s.Confidence.Level = sidecar.ConfidenceModerate
	s.DeviceRecommendation = &sidecar.DeviceRecommendation{Devices: []string{"/dev/kvm"}}
	if err := writeDeviceComposeLintProfile(&strings.Builder{}, s, false); err == nil {
		t.Fatal("expected contract failure without --allow-exploratory")
	}
	// With the escape hatch it emits, wrapped under exploratory:.
	var b strings.Builder
	if err := writeDeviceComposeLintProfile(&b, s, true); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "exploratory:") {
		t.Errorf("exploratory output should be wrapped:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "image_digest missing") {
		t.Errorf("violations should be listed:\n%s", b.String())
	}
}

func TestCheckDeviceComposeLintContractReplicaDisagreement(t *testing.T) {
	wl := t.TempDir() + "/w.sh"
	_ = os.WriteFile(wl, []byte("x"), 0o644)
	s := fullyValidDeviceSidecar(wl)
	s.Target.ReplicaDeviceDisagreement = []string{"/dev/net/tun"}
	v := checkDeviceComposeLintContract(s)
	found := false
	for _, msg := range v {
		if strings.Contains(msg, "replica_device_disagreement") {
			found = true
		}
	}
	if !found {
		t.Errorf("replica device disagreement should be a contract violation: %v", v)
	}
}
