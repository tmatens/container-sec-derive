package main

import (
	"reflect"
	"testing"
)

func TestDeviceToRecommendation(t *testing.T) {
	// Devices pass through in order; no hinted device → no derived caps.
	rec := deviceToRecommendation([]string{"/dev/dri/card0", "/dev/dri/renderD128", "/dev/kvm"})
	if !reflect.DeepEqual(rec.Devices, []string{"/dev/dri/card0", "/dev/dri/renderD128", "/dev/kvm"}) {
		t.Errorf("devices = %v", rec.Devices)
	}
	if rec.DerivedCaps != nil {
		t.Errorf("derived caps = %v, want nil (no hinted device)", rec.DerivedCaps)
	}
}

func TestDeviceToRecommendationDerivedCap(t *testing.T) {
	// /dev/net/tun is the one seeded hint → CAP_NET_ADMIN.
	rec := deviceToRecommendation([]string{"/dev/net/tun", "/dev/sda"})
	if !reflect.DeepEqual(rec.DerivedCaps, []string{"CAP_NET_ADMIN"}) {
		t.Errorf("derived caps = %v, want [CAP_NET_ADMIN]", rec.DerivedCaps)
	}
}

func TestDeviceToRecommendationIndependentSlice(t *testing.T) {
	// The recommendation must not alias the caller's slice — a later mutation of
	// the input must not corrupt the recommendation.
	in := []string{"/dev/kvm"}
	rec := deviceToRecommendation(in)
	in[0] = "/dev/mutated"
	if rec.Devices[0] != "/dev/kvm" {
		t.Errorf("recommendation aliased input slice: %v", rec.Devices)
	}
}
