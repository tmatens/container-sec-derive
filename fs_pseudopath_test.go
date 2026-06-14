package main

import (
	"strings"
	"testing"
)

func TestIsRootfsWrite(t *testing.T) {
	keep := []string{"/var/log/app.log", "/run/postgresql/.s.PGSQL.5432.lock", "/tmp/x", "/csd-exerciser-target"}
	drop := []string{
		"/proc/106/task/106/attr/apparmor", "/proc", "/sys/fs/cgroup/x", "/sys",
		"/dev/shm/foo", "/dev", "base/5", "relative/path", "",
		"/procfs-not-proc/x", // sanity: only exact /proc[/...] is excluded
	}
	for _, p := range keep {
		if !isRootfsWrite(p) {
			t.Errorf("isRootfsWrite(%q) = false, want true", p)
		}
	}
	for _, p := range drop[:len(drop)-1] {
		if isRootfsWrite(p) {
			t.Errorf("isRootfsWrite(%q) = true, want false", p)
		}
	}
	// /procfs-not-proc is a real rootfs path, not procfs — must be kept.
	if !isRootfsWrite("/procfs-not-proc/x") {
		t.Error("isRootfsWrite(/procfs-not-proc/x) = false; only /proc and /proc/* should be excluded")
	}
}

// The aggregator must drop pseudo-fs and relative writes end-to-end so they
// never reach writable_paths, the recommendation, or the event count.
func TestAggregateWrites_FiltersPseudoPaths(t *testing.T) {
	const nd = `
{"syscall":"openat","flags_raw":1,"fpath":"/var/log/app.log","proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"web-1","containerImageName":"web:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"/proc/71/task/71/attr/apparmor","proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"web-1","containerImageName":"web:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"/dev/shm/x","proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"web-1","containerImageName":"web:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"base/5","proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"web-1","containerImageName":"web:1"}}
`
	obs, err := aggregateWrites(strings.NewReader(nd), aggregateOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if obs.EventCount != 1 {
		t.Errorf("event count = %d, want 1 (only /var/log/app.log is a rootfs write)", obs.EventCount)
	}
	if len(obs.Paths) != 1 || obs.Paths[0] != "/var/log/app.log" {
		t.Errorf("paths = %v, want [/var/log/app.log]", obs.Paths)
	}
}
