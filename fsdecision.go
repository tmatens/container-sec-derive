package main

import (
	"path"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// pseudoFSPrefixes are kernel virtual-filesystem mount points. Writes under
// them are not container-rootfs writes: /proc and /sys are procfs/sysfs (a
// read-only rootfs does not cover them and they cannot be backed by tmpfs), and
// /dev is a runtime-managed devtmpfs (/dev/shm is already tmpfs). The v0.2 fs
// observer's read_only/tmpfs recommendation concerns the rootfs only.
var pseudoFSPrefixes = []string{"/proc", "/sys", "/dev"}

// isRootfsWrite reports whether p is a write the read_only/tmpfs recommendation
// can act on: an absolute path not under a kernel pseudo-filesystem. It filters
// two classes the live #86 run surfaced as noise in the postgres observation:
//   - pseudo-fs writes (e.g. /proc/<pid>/task/<tid>/attr/apparmor, /dev/shm) —
//     separate mounts a read-only rootfs doesn't touch; recommending tmpfs for
//     them is meaningless.
//   - relative paths (e.g. "base/5") — an openat with a dirfd that ig couldn't
//     resolve to an absolute fpath; it cannot be turned into a tmpfs entry.
func isRootfsWrite(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for _, pre := range pseudoFSPrefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return false
		}
	}
	return true
}

// correlateWrites classifies the observed write paths against the container's
// mount destinations. Writes at or below a mount are volume-covered; the rest
// are rootfs writes whose parent directories become tmpfs candidates (grouped
// by directory prefix and collapsed to ancestors). `read_only: true` is always
// the recommendation — tmpfs covers the incidental rootfs writes. writePaths is
// expected sorted (as aggregateWrites returns it).
//
// Foot-gun (issue #77): csd does NOT try to decide whether a rootfs write is
// disposable cache or data that needs persistence. TmpfsPaths are emitted as
// tmpfs *candidates*; a human reviews whether any belongs in a real volume.
// csd never silently turns data writes into tmpfs.
func correlateWrites(writePaths, mounts []string) sidecar.FSRecommendation {
	rec := sidecar.FSRecommendation{ReadOnly: true}
	tmpfs := map[string]struct{}{}
	for _, p := range writePaths {
		if underAnyMount(p, mounts) {
			rec.VolumeCovered = append(rec.VolumeCovered, p)
			continue
		}
		tmpfs[path.Dir(p)] = struct{}{}
	}
	rec.TmpfsPaths = collapseToAncestors(sortedKeys(tmpfs))
	return rec
}

// underAnyMount reports whether p is at or below one of the mount destinations.
func underAnyMount(p string, mounts []string) bool {
	for _, m := range mounts {
		if m == "" {
			continue
		}
		if p == m || strings.HasPrefix(p, strings.TrimSuffix(m, "/")+"/") {
			return true
		}
	}
	return false
}

// collapseToAncestors drops any path that already has an ancestor in the set,
// so {/var/log, /var/log/app} collapses to {/var/log}. Input must be sorted so
// ancestors precede descendants; output stays sorted.
func collapseToAncestors(dirs []string) []string {
	var out []string
	for _, d := range dirs {
		covered := false
		for _, o := range out {
			if d == o || strings.HasPrefix(d, strings.TrimSuffix(o, "/")+"/") {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, d)
		}
	}
	return out
}
