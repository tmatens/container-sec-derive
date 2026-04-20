package main

import (
	"fmt"
	"io"
	"strings"
)

// writeDockerRun emits a `docker run` flag string that realizes the derived
// cap profile: `--cap-drop=ALL` followed by one `--cap-add=NAME` per observed
// capability, space-separated on a single line so users can paste directly
// into an existing `docker run ...` invocation. Bare cap names (no `CAP_`
// prefix) match Docker's accepted form and the compose-lint profile shape
// (PLAN.md §Contribution loop with compose-lint).
//
// `--cap-add` is omitted entirely when the observed set is empty -- the
// "drop everything, add nothing" shape mirrors writeCompose's elision.
func writeDockerRun(w io.Writer, s *Sidecar) error {
	parts := []string{"--cap-drop=ALL"}
	for _, c := range s.CapNames() {
		parts = append(parts, "--cap-add="+c)
	}
	_, err := fmt.Fprintln(w, strings.Join(parts, " "))
	return err
}
