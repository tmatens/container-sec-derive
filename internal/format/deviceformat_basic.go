package format

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// The v0.3 device formatters below mirror the cap formatters (docker_run.go /
// k8s.go / oci.go) and the fs formatters (fsformat_basic.go), but express the
// device-decomposition recommendation: the minimum set of non-default /dev
// nodes a privileged container actually opened. Derived-capability hints are
// emitted as comments only (the device observer did not observe capabilities,
// so it must not presume a cap grant — confirm via --observe caps / privileged).
// An empty recommendation yields the cleanest valid shape: a comment stating no
// non-default devices were observed, i.e. no device grant is required.

// WriteDeviceDockerRun emits a `docker run` flag string realizing the device
// recommendation: one `--device <node>:<node>` per observed node, space-
// separated for pasting into an existing `docker run`. Derived-cap hints follow
// as `#`-comment lines (shell-safe), pointing at the cap-observing modes.
func WriteDeviceDockerRun(w io.Writer, rec sidecar.DeviceRecommendation) error {
	if len(rec.Devices) == 0 {
		_, err := fmt.Fprintln(w, "# no non-default device opens observed; no --device flags required")
		return err
	}
	parts := make([]string, 0, len(rec.Devices))
	for _, d := range rec.Devices {
		parts = append(parts, fmt.Sprintf("--device %s:%s", d, d))
	}
	if _, err := fmt.Fprintln(w, strings.Join(parts, " ")); err != nil {
		return err
	}
	for _, c := range rec.DerivedCaps {
		if _, err := fmt.Fprintf(w, "# note: a granted device typically requires --cap-add %s; confirm with --observe caps / --observe privileged\n", c); err != nil {
			return err
		}
	}
	return nil
}

// WriteDeviceK8s emits a Kubernetes block for the device recommendation.
// Kubernetes has NO per-device grant in the core SecurityContext — device
// access is mediated by the device-plugin framework (e.g. intel.com/gpu,
// smarter-devices) or, bluntly, `privileged: true`. So rather than fabricate a
// false-precision SecurityContext, this emits the concrete decomposition
// conclusion (`securityContext.privileged: false`) plus a `#`-commented list of
// the observed nodes and a pointer to device plugins. This is the design call
// recorded in issue #92 (open question 2).
func WriteDeviceK8s(w io.Writer, rec sidecar.DeviceRecommendation) error {
	if len(rec.Devices) == 0 {
		if _, err := fmt.Fprintln(w, "# no non-default device opens observed; no device-plugin grant required"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "# Kubernetes has no per-device grant in the core SecurityContext."); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "# The container opened these non-default device node(s):"); err != nil {
			return err
		}
		for _, d := range rec.Devices {
			if _, err := fmt.Fprintf(w, "#   - %s\n", d); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w, "# Grant them via the device-plugin framework (e.g. intel.com/gpu, smarter-devices) — not privileged: true."); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "securityContext:"); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "  privileged: false")
	return err
}

// WriteDeviceOCI emits an OCI runtime spec snippet for the device
// recommendation. An OCI `linux.devices` entry requires the device's major and
// minor numbers, which trace_open does NOT report (csd observes paths, not
// device numbers), so emitting a `linux.devices` array would produce an
// unrealizable spec. Instead the observed nodes are carried in the spec's
// free-form, always-valid `annotations` map, with a note telling the operator
// how to resolve the numbers on the host. Users merge this against an existing
// config.json; the annotations are inert to runtimes that don't read them and
// informative to those (and humans) that do.
func WriteDeviceOCI(w io.Writer, rec sidecar.DeviceRecommendation) error {
	annotations := map[string]string{}
	if len(rec.Devices) == 0 {
		annotations["org.containersecderive.observed-devices"] = ""
		annotations["org.containersecderive.devices-note"] = "no non-default device opens observed; no linux.devices grant required"
	} else {
		annotations["org.containersecderive.observed-devices"] = strings.Join(rec.Devices, ",")
		annotations["org.containersecderive.devices-note"] = "csd observes device paths, not numbers; resolve each node's major/minor on the host (e.g. `stat -c '%t:%T' <path>`) to populate linux.devices."
		if len(rec.DerivedCaps) > 0 {
			annotations["org.containersecderive.derived-caps"] = strings.Join(rec.DerivedCaps, ",")
		}
	}
	snippet := struct {
		Annotations map[string]string `json:"annotations"`
	}{Annotations: annotations}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// The devices-note carries `<path>`; without this it serializes as the
	// escaped <path>. config.json is not HTML, so plain `<` is fine
	// and keeps the operator-facing note readable.
	enc.SetEscapeHTML(false)
	return enc.Encode(snippet)
}
