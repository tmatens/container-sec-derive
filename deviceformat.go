package main

import (
	"fmt"
	"io"
)

// writeDeviceCompose emits the docker-compose `devices:` stanza for the v0.3
// device-decomposition recommendation: one `HOST:CONTAINER` mapping per
// observed non-default device node. Block style, matching writeCompose /
// writeFSCompose, so it pastes under a service and diffs cleanly.
//
// When no non-default devices were observed, a single `#`-comment says so —
// the actionable conclusion is that the container needs no `devices:` grant
// (and, in the composition path, no `privileged: true` on the device axis).
//
// Derived-capability hints are emitted only as `#`-comments: the device
// observer alone did not observe capabilities, so it must not presume a
// `cap_add:` the workload may not need. The comment points the user at
// `--observe caps` / `--observe privileged`, which confirm the cap from
// observed trace_capabilities events rather than the static hint table.
func writeDeviceCompose(w io.Writer, rec deviceRecommendation) error {
	if len(rec.Devices) == 0 {
		_, err := fmt.Fprintln(w, "# no non-default device opens observed; no devices: grant required")
		return err
	}
	if _, err := fmt.Fprintln(w, "devices:"); err != nil {
		return err
	}
	for _, d := range rec.Devices {
		if _, err := fmt.Fprintf(w, "  - %s:%s\n", d, d); err != nil {
			return err
		}
	}
	for _, c := range rec.DerivedCaps {
		if _, err := fmt.Fprintf(w, "# note: a granted device typically requires %s; confirm with --observe caps / --observe privileged\n", c); err != nil {
			return err
		}
	}
	return nil
}
