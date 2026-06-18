package format

import (
	"fmt"
	"io"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// WriteDockerRun emits a `docker run` flag string that realizes the derived
// cap profile: `--cap-drop=ALL` followed by one `--cap-add=NAME` per observed
// capability, space-separated on a single line so users can paste directly
// into an existing `docker run ...` invocation. Bare cap names (no `CAP_`
// prefix) match Docker's accepted form and the compose-lint profile shape
// (PLAN.md §Contribution loop with compose-lint).
//
// `--cap-add` is omitted entirely when the observed set is empty -- the
// "drop everything, add nothing" shape mirrors WriteCompose's elision.
func WriteDockerRun(w io.Writer, s *sidecar.Sidecar) error {
	parts := []string{"--cap-drop=ALL"}
	for _, c := range s.CapNames() {
		parts = append(parts, "--cap-add="+c)
	}
	_, err := fmt.Fprintln(w, strings.Join(parts, " "))
	return err
}
