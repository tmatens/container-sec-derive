package format

import (
	"fmt"
	"io"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// WriteFSCompose emits the docker-compose stanza for the v0.2 read-only-fs
// recommendation: `read_only: true`, plus a `tmpfs:` list of the writable
// paths not backed by a volume. Block style, matching WriteCompose, so it
// pastes under a service and diffs cleanly.
//
// When there are no rootfs writes (every observed write was volume-covered),
// only `read_only: true` is emitted — the cleanest valid shape. When tmpfs
// entries are present a `#`-comment flags them for review: csd cannot tell a
// disposable cache write from data that needs persistence, so a human decides
// whether any tmpfs path should instead be a volume (issue #77 foot-gun). The
// comment is YAML-safe, so the output stays paste-ready.
func WriteFSCompose(w io.Writer, rec sidecar.FSRecommendation) error {
	if _, err := fmt.Fprintln(w, "read_only: true"); err != nil {
		return err
	}
	if len(rec.TmpfsPaths) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "# review: tmpfs entries are writable paths not on a volume;"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "# move any that must persist to a volume instead."); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "tmpfs:"); err != nil {
		return err
	}
	for _, p := range rec.TmpfsPaths {
		if _, err := fmt.Fprintf(w, "  - %s\n", p); err != nil {
			return err
		}
	}
	return nil
}
