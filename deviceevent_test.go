package main

import (
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
)

func TestIsDeviceOpen(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Non-default device nodes privileged unlocks — the signal.
		{"/dev/dri/card0", true},
		{"/dev/dri/renderD128", true},
		{"/dev/kvm", true},
		{"/dev/net/tun", true},
		{"/dev/fuse", true},
		{"/dev/sda", true},
		{"/dev/mapper/cryptroot", true},
		{"/dev/snd/pcmC0D0p", true},
		{"/dev/nvidia0", true},
		// Default container devices — always present unprivileged, excluded.
		{"/dev/null", false},
		{"/dev/zero", false},
		{"/dev/full", false},
		{"/dev/random", false},
		{"/dev/urandom", false},
		{"/dev/tty", false},
		{"/dev/console", false},
		{"/dev/ptmx", false},
		{"/dev/stdin", false},
		// Standard /dev mounts and their children — not device grants.
		{"/dev/pts/0", false},
		{"/dev/shm", false},
		{"/dev/shm/sem.x", false},
		{"/dev/mqueue", false},
		{"/dev/mqueue/q", false},
		// The /dev directory itself, and non-/dev paths.
		{"/dev", false},
		{"/dev/", false},
		{"/var/lib/x", false},
		{"/proc/1/status", false},
		{"relative/dev/x", false},
	}
	for _, c := range cases {
		if got := isDeviceOpen(c.path); got != c.want {
			t.Errorf("isDeviceOpen(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestAggregateDevices(t *testing.T) {
	// Two replicas. Includes a default device (/dev/null) and a read-only open
	// of a real device (/dev/dri/card0, flags_raw=0=O_RDONLY) that must still
	// count — device access is not write-gated.
	const nd = `
{"syscall":"openat","flags_raw":0,"fpath":"/dev/dri/card0","proc":{"comm":"X"},"runtime":{"containerId":"aaa111aaa111","containerName":"gpu-1","containerImageName":"gpu:1"}}
{"syscall":"openat","flags_raw":2,"fpath":"/dev/dri/renderD128","proc":{"comm":"X"},"runtime":{"containerId":"aaa111aaa111","containerName":"gpu-1","containerImageName":"gpu:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"/dev/null","proc":{"comm":"X"},"runtime":{"containerId":"aaa111aaa111","containerName":"gpu-1","containerImageName":"gpu:1"}}
{"syscall":"openat","flags_raw":2,"fpath":"/dev/net/tun","proc":{"comm":"vpn"},"runtime":{"containerId":"bbb222bbb222","containerName":"vpn-1","containerImageName":"vpn:1"}}
`
	obs, err := aggregateDevices(strings.NewReader(nd), attrib.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if obs.EventCount != 3 {
		t.Errorf("event count = %d, want 3 (/dev/null excluded)", obs.EventCount)
	}
	if len(obs.PerReplica) != 2 {
		t.Errorf("replicas = %d, want 2", len(obs.PerReplica))
	}
	want := []string{"/dev/dri/card0", "/dev/dri/renderD128", "/dev/net/tun"}
	if len(obs.Devices) != len(want) {
		t.Fatalf("union devices = %v, want %v", obs.Devices, want)
	}
	for i, d := range want {
		if obs.Devices[i] != d {
			t.Errorf("Devices[%d] = %q, want %q (should be sorted)", i, obs.Devices[i], d)
		}
	}
	if st := obs.Stats["/dev/dri/card0"]; st == nil || st.eventCount != 1 {
		t.Errorf("stats for /dev/dri/card0 = %+v, want eventCount 1", st)
	}

	// Target selection: only gpu-1's devices.
	sel, err := aggregateDevices(strings.NewReader(nd), attrib.Opts{Container: "gpu-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Devices) != 2 || len(sel.PerReplica) != 1 {
		t.Errorf("selected gpu-1: devices=%v replicas=%d, want 2 devices / 1 replica", sel.Devices, len(sel.PerReplica))
	}
}

func TestAggregateDevicesImageAmbiguity(t *testing.T) {
	// --image matching >1 replica without --all-matching is an error, mirroring
	// the cap and fs aggregators.
	const nd = `
{"syscall":"openat","flags_raw":2,"fpath":"/dev/kvm","proc":{"comm":"q"},"runtime":{"containerId":"aaa111aaa111","containerName":"vm-1","containerImageName":"vm:1"}}
{"syscall":"openat","flags_raw":2,"fpath":"/dev/kvm","proc":{"comm":"q"},"runtime":{"containerId":"bbb222bbb222","containerName":"vm-2","containerImageName":"vm:1"}}
`
	if _, err := aggregateDevices(strings.NewReader(nd), attrib.Opts{Image: "vm:1"}); err == nil {
		t.Fatal("expected ambiguous-selection error for >1 replica under --image")
	}
	// --all-matching unions them.
	obs, err := aggregateDevices(strings.NewReader(nd), attrib.Opts{Image: "vm:1", AllMatching: true})
	if err != nil {
		t.Fatalf("--all-matching should union, got %v", err)
	}
	if len(obs.PerReplica) != 2 || len(obs.Devices) != 1 {
		t.Errorf("all-matching: devices=%v replicas=%d, want 1 device / 2 replicas", obs.Devices, len(obs.PerReplica))
	}
}
