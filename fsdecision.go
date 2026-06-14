package main

import (
	"path"
	"strings"
)

// fsRecommendation is the v0.2 read-only-filesystem decision derived from the
// observed write paths and the container's mount configuration:
//   - ReadOnly is the headline recommendation (compose `read_only: true`).
//   - TmpfsPaths are directory prefixes that must be writable but are not backed
//     by a volume — incidental runtime state, mounted `tmpfs:`.
//   - VolumeCovered are observed writes already satisfied by an existing
//     bind-mount / named volume (informational; left as-is).
//
// Foot-gun (issue #77): csd does NOT try to decide whether a rootfs write is
// disposable cache or data that needs persistence. TmpfsPaths are emitted as
// tmpfs *candidates*; a human reviews whether any belongs in a real volume.
// csd never silently turns data writes into tmpfs.
type fsRecommendation struct {
	ReadOnly      bool     `json:"read_only"`
	TmpfsPaths    []string `json:"tmpfs_paths"`
	VolumeCovered []string `json:"volume_covered"`
}

// correlateWrites classifies the observed write paths against the container's
// mount destinations. Writes at or below a mount are volume-covered; the rest
// are rootfs writes whose parent directories become tmpfs candidates (grouped
// by directory prefix and collapsed to ancestors). `read_only: true` is always
// the recommendation — tmpfs covers the incidental rootfs writes. writePaths is
// expected sorted (as aggregateWrites returns it).
func correlateWrites(writePaths, mounts []string) fsRecommendation {
	rec := fsRecommendation{ReadOnly: true}
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
