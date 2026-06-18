package format

import (
	"fmt"
	"io"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// WriteDeviceComposePatch emits a unified diff that sets services.<service>'s
// `devices:` block to the v0.3 device recommendation. It is the device analog of
// WriteFSComposePatch and reuses the same stdlib compose-locator + rewrite +
// unified-diff machinery (locateComposeService / findChildKeyBlock / capRewrite
// / markRewrites / emitUnifiedDiff); only the block being written differs — a
// `devices:` sequence of `<node>:<node>` mappings.
//
// An empty recommendation proposes NO change: it leaves any existing `devices:`
// block untouched rather than removing it. This mirrors the fs patch's
// treatment of an empty tmpfs set (issue #92 foot-gun) — an empty observation
// is far more likely under-coverage than positive evidence the user's device
// grants are unnecessary, and silently proposing to delete a declared device is
// exactly what csd must not do. Dropping `privileged: true` itself is the
// composition path's job (the device observer alone does not observe caps), so
// this patch only manages the `devices:` block.
func WriteDeviceComposePatch(w io.Writer, rec sidecar.DeviceRecommendation, original []byte, inPath, service string) error {
	if service == "" {
		return fmt.Errorf("--service is required")
	}
	if len(rec.Devices) == 0 {
		return nil
	}
	origLines, eol, finalNL := splitComposeLines(original)
	loc, err := locateComposeService(origLines, service)
	if err != nil {
		return err
	}

	bodyIndent := strings.Repeat(" ", loc.bodyIndent)
	childIndent := bodyIndent + "  "
	newDevices := []string{bodyIndent + "devices:"}
	for _, d := range rec.Devices {
		newDevices = append(newDevices, fmt.Sprintf("%s- %s:%s", childIndent, d, d))
	}

	var rewrites []capRewrite
	if start, end := findChildKeyBlock(origLines, loc, "devices"); start >= 0 {
		rewrites = append(rewrites, capRewrite{start, end, newDevices})
	} else {
		rewrites = append(rewrites, capRewrite{loc.bodyStart, loc.bodyStart, newDevices})
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
