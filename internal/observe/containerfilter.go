// In-gadget container filtering: when a run targets one --container, pass the
// gadget's own `--containername` filter so events from every other process on
// the host never enter the perf buffer. Without it the gadget streams
// host-wide and userspace attribution discards the noise AFTER it has competed
// for buffer space — on a busy host (or against a chatty target like a
// pid:host monitor) that overflows the ring buffer and blows the <1%
// trace_health.drop_rate acceptance contract even though every dropped event
// was one attribution would have discarded anyway.
//
// This narrows only the kernel-side stream; the attribution layer still
// matches every event, so a too-narrow filter can only lose events the run
// would not have attributed. Filtering is observer-agnostic (every gadget
// spawn wants it), so it lives here next to PopulateImageDigest.
package observe

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// GadgetContainerFilter returns the extra `ig run` args that filter the gadget
// to the targeted container, or nil when the run must stay host-wide.
//
// The gadget flag matches the runtime-assigned container NAME, while csd's
// --container accepts an id or id-prefix too, so the name is resolved via
// `<runtime> inspect` first. Resolution failure is non-fatal: the run falls
// back to unfiltered observation (the pre-filter behavior — correct, just
// drop-prone) with a stderr note. --image selection stays unfiltered because
// its replicas are discovered per-event during attribution.
func GadgetContainerFilter(container, runtimeBin string, stderrSink io.Writer) []string {
	if container == "" {
		return nil
	}
	if runtimeBin == "" {
		runtimeBin = "docker"
	}
	ctx, cancel := context.WithTimeout(context.Background(), InspectDefaultTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, runtimeBin, "inspect", "--format", "{{.Name}}", "--", container).Output()
	if err != nil {
		if stderrSink != nil {
			fmt.Fprintf(stderrSink, "csd: container-name lookup for the gadget filter unavailable (%v); observing host-wide\n", err)
		}
		return nil
	}
	// docker/podman report the name with a leading slash.
	name := strings.TrimPrefix(strings.TrimSpace(string(out)), "/")
	if name == "" {
		return nil
	}
	return []string{"--containername", name}
}
