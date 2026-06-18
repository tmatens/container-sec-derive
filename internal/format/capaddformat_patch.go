package format

import (
	"fmt"
	"io"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// WriteCapaddComposePatch emits a unified diff that rewrites
// services.<service>'s `cap_add:` block to the v0.5 recommended minimized set
// (finer substitutions applied, unused caps dropped). It reuses the same stdlib
// compose-locator + rewrite + unified-diff machinery as the cap/device patches
// (locateComposeService / findChildKeyBlock / capRewrite / markRewrites /
// emitUnifiedDiff).
//
// A patch is only meaningful when the user supplied the granted set (--cap-add):
// without it there is no recommendation to apply, so this proposes NO change
// (mirroring the device patch's treatment of an empty recommendation). When the
// recommendation is the empty set (every validated cap was unused) the block is
// rewritten to `cap_add: []` — an explicit, reviewable minimization rather than a
// silent deletion.
func WriteCapaddComposePatch(w io.Writer, val *sidecar.CapaddValidation, original []byte, inPath, service string) error {
	if service == "" {
		return fmt.Errorf("--service is required")
	}
	if !val.GrantedSetProvided {
		return nil
	}
	origLines, eol, finalNL := splitComposeLines(original)
	loc, err := locateComposeService(origLines, service)
	if err != nil {
		return err
	}

	bodyIndent := strings.Repeat(" ", loc.bodyIndent)
	childIndent := bodyIndent + "  "
	var newCapAdd []string
	if len(val.RecommendedCapAdd) == 0 {
		newCapAdd = []string{bodyIndent + "cap_add: []"}
	} else {
		newCapAdd = append(newCapAdd, bodyIndent+"cap_add:")
		for _, c := range val.RecommendedCapAdd {
			newCapAdd = append(newCapAdd, fmt.Sprintf("%s- %s", childIndent, c))
		}
	}

	var rewrites []capRewrite
	if start, end := findChildKeyBlock(origLines, loc, "cap_add"); start >= 0 {
		rewrites = append(rewrites, capRewrite{start, end, newCapAdd})
	} else {
		rewrites = append(rewrites, capRewrite{loc.bodyStart, loc.bodyStart, newCapAdd})
	}

	if err := refuseAnchoredRewrites(origLines, rewrites); err != nil {
		return err
	}
	edited := applyRewriteSequence(origLines, rewrites)
	if equalLines(origLines, edited) {
		return nil
	}
	marks := markRewrites(origLines, rewrites)
	return emitUnifiedDiff(w, inPath, marks, eol, finalNL)
}
