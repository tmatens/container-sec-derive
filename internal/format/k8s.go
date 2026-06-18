package format

import (
	"fmt"
	"io"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// WriteK8s emits a Kubernetes `securityContext.capabilities` YAML block
// derived from s.CapNames(). Users paste the output under a container
// spec (pod, deployment, statefulset, etc.) -- indentation is two-space
// block style so it drops in under `containers: - name: foo` at the
// canonical indent depth. Bare cap names (no `CAP_` prefix) match the
// core/v1 SecurityContext.Capabilities shape; k8s accepts either form
// but the bare form is idiomatic and matches compose / docker-run output.
//
// drop: [ALL] is always emitted. add is omitted entirely when the
// observed set is empty -- the "drop everything, add nothing" shape
// mirrors WriteCompose and WriteDockerRun.
func WriteK8s(w io.Writer, s *sidecar.Sidecar) error {
	if _, err := fmt.Fprintln(w, "securityContext:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  capabilities:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "    drop:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "      - ALL"); err != nil {
		return err
	}
	caps := s.CapNames()
	if len(caps) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "    add:"); err != nil {
		return err
	}
	for _, c := range caps {
		if _, err := fmt.Fprintf(w, "      - %s\n", c); err != nil {
			return err
		}
	}
	return nil
}
