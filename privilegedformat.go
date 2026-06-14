package main

import (
	"fmt"
	"io"
)

// The v0.3 privileged formatters compose the existing capability and device
// formatters: the minimum non-privileged equivalent of `privileged: true` IS
// the observed cap set (the cap formatter's output) plus the observed device
// nodes (the device formatter's output). Reusing the single-observer formatters
// keeps one source of truth per output shape; the privileged variant only adds
// the "drop privileged: true" framing and stitches the two halves together.
// JSON needs no privileged variant — writeJSON already serializes the full
// sidecar (capabilities + device_recommendation + privileged_decomposition).

// writePrivilegedCompose emits the compose decomposition of `privileged: true`:
// a drop-privileged header, then the capability stanza (cap_drop: [ALL] +
// cap_add), then the device stanza (devices:). The result pastes under a
// service in place of `privileged: true`.
func writePrivilegedCompose(w io.Writer, s *Sidecar) error {
	if _, err := fmt.Fprintln(w, "# privileged: true is not required; drop it and apply the minimum below:"); err != nil {
		return err
	}
	if err := writeCompose(w, s); err != nil {
		return err
	}
	if s.DeviceRecommendation != nil {
		if err := writeDeviceCompose(w, *s.DeviceRecommendation); err != nil {
			return err
		}
	}
	return nil
}
