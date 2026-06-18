package main

import (
	"fmt"
	"io"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// Format identifiers. v0.1.0-beta ships only `compose`; the remaining six
// land in v0.1.0-rc (PLAN.md §v0.1 build order). The constant set is
// centralized so the "supported formats" list has one source of truth.
const (
	FormatCompose          = "compose"
	FormatComposePatch     = "compose-patch"        // v0.1.0-rc
	FormatDockerRun        = "docker-run"           // v0.1.0-rc
	FormatOCI              = "oci"                  // v0.1.0-rc
	FormatK8s              = "k8s"                  // v0.1.0-rc
	FormatJSON             = "json"                 // v0.1.0-rc
	FormatComposeLintEntry = "compose-lint-profile" // v0.1.0-rc
	FormatNftables         = "nftables"             // v0.8 egress-only
	FormatK8sNetworkPolicy = "k8s-networkpolicy"    // v0.8 egress-only
)

// writeCompose emits a docker-compose cap_drop/cap_add stanza derived from
// s.CapNames(). Format matches compose v3 syntax -- users paste the output
// under the target service in their compose file. Block style (not flow)
// because it diffs cleanly when the cap set changes across digest bumps.
//
// cap_drop: [ALL] is always emitted. cap_add is omitted entirely when the
// observed set is empty, which is the valid compose shape for "drop
// everything, add nothing."
func writeCompose(w io.Writer, s *sidecar.Sidecar) error {
	if _, err := fmt.Fprintln(w, "cap_drop:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  - ALL"); err != nil {
		return err
	}
	caps := s.CapNames()
	if len(caps) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "cap_add:"); err != nil {
		return err
	}
	for _, c := range caps {
		if _, err := fmt.Fprintf(w, "  - %s\n", c); err != nil {
			return err
		}
	}
	return nil
}
