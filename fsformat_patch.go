package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// writeFSComposePatch emits a unified diff that sets services.<service>'s
// read_only/tmpfs to the v0.2 fs recommendation. It is the fs analog of
// writeComposePatch and reuses the same stdlib compose-locator + rewrite +
// unified-diff machinery (locateComposeService / findChildKeyBlock /
// capRewrite / markRewrites / emitUnifiedDiff); only the blocks being written
// differ — `read_only: true` (a scalar) and a `tmpfs:` sequence.
//
// read_only is always set true (the headline recommendation). tmpfs is only
// managed when csd actually derived tmpfs candidates: an empty derived set
// leaves any existing `tmpfs:` block untouched rather than removing it. This
// diverges deliberately from the cap patch (which removes cap_add on an empty
// set): for the fs observer an empty observation is far more likely
// under-coverage than positive evidence that the user's tmpfs is unnecessary,
// and silently proposing to delete a declared tmpfs is the issue-#77 foot-gun.
// VolumeCovered paths are never emitted — the user's existing mounts satisfy
// them.
func writeFSComposePatch(w io.Writer, rec fsRecommendation, original []byte, inPath, service string) error {
	if service == "" {
		return fmt.Errorf("--service is required")
	}
	origLines := splitComposeLines(original)
	loc, err := locateComposeService(origLines, service)
	if err != nil {
		return err
	}

	bodyIndent := strings.Repeat(" ", loc.bodyIndent)
	childIndent := bodyIndent + "  "
	newReadOnly := []string{bodyIndent + "read_only: true"}
	var newTmpfs []string
	manageTmpfs := len(rec.TmpfsPaths) > 0
	if manageTmpfs {
		newTmpfs = append(newTmpfs, bodyIndent+"tmpfs:")
		for _, p := range rec.TmpfsPaths {
			newTmpfs = append(newTmpfs, childIndent+"- "+p)
		}
	}
	combined := append(append([]string{}, newReadOnly...), newTmpfs...)

	roStart, roEnd := findChildKeyBlock(origLines, loc, "read_only")
	tmStart, tmEnd := findChildKeyBlock(origLines, loc, "tmpfs")
	roExists := roStart >= 0
	tmExists := tmStart >= 0

	var rewrites []capRewrite
	switch {
	case !manageTmpfs:
		// Only set read_only; never touch an existing tmpfs block.
		if roExists {
			rewrites = append(rewrites, capRewrite{roStart, roEnd, newReadOnly})
		} else {
			rewrites = append(rewrites, capRewrite{loc.bodyStart, loc.bodyStart, newReadOnly})
		}
	case roExists && tmExists:
		rewrites = append(rewrites, capRewrite{roStart, roEnd, newReadOnly})
		rewrites = append(rewrites, capRewrite{tmStart, tmEnd, newTmpfs})
	case roExists && !tmExists:
		rewrites = append(rewrites, capRewrite{roStart, roEnd, combined})
	case !roExists && tmExists:
		rewrites = append(rewrites, capRewrite{tmStart, tmEnd, combined})
	default:
		rewrites = append(rewrites, capRewrite{loc.bodyStart, loc.bodyStart, combined})
	}
	sort.Slice(rewrites, func(i, j int) bool { return rewrites[i].start < rewrites[j].start })

	edited := applyRewriteSequence(origLines, rewrites)
	if equalLines(origLines, edited) {
		return nil
	}
	marks := markRewrites(origLines, rewrites)
	return emitUnifiedDiff(w, inPath, marks)
}
