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
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// GadgetContainerFilter returns the extra `ig run` args that filter the gadget
// to the targeted container, or nil when the run must stay host-wide.
//
// The filter value must be the name IG itself attributes to the container,
// which can diverge from the runtime CLI's view (under Docker 29's containerd
// image store the hosted-runner smoke saw ig attribute a name the docker-side
// name filter never matched, yielding a zero-event observation). So the
// target's container ID is resolved via `<runtime> inspect` (csd's
// --container accepts a name or id/prefix) and then looked up in
// `ig list-containers`; the filter uses IG's own containerName for that ID.
// Any miss — inspect failure, ig lookup failure, ID absent from ig's view,
// empty name — is non-fatal: the run falls back to unfiltered observation
// (the pre-filter behavior — correct, just drop-prone) with a stderr note.
// --image selection stays unfiltered because its replicas are discovered
// per-event during attribution.
func GadgetContainerFilter(container, runtimeBin, igBin string, stderrSink io.Writer) []string {
	if container == "" {
		return nil
	}
	if runtimeBin == "" {
		runtimeBin = "docker"
	}
	ctx, cancel := context.WithTimeout(context.Background(), InspectDefaultTimeout)
	defer cancel()
	hostWide := func(why string) []string {
		if stderrSink != nil {
			fmt.Fprintf(stderrSink, "csd: gadget container filter unavailable (%s); observing host-wide\n", why)
		}
		return nil
	}
	out, err := exec.CommandContext(ctx, runtimeBin, "inspect", "--format", "{{.Id}}", "--", container).Output()
	if err != nil {
		return hostWide(fmt.Sprintf("%s inspect %s: %v", runtimeBin, container, err))
	}
	id := strings.TrimSpace(string(out))
	if id == "" {
		return hostWide("container id resolved empty")
	}
	name, err := igContainerName(ctx, igBin, id)
	if err != nil {
		return hostWide(fmt.Sprintf("ig list-containers: %v", err))
	}
	if name == "" {
		return hostWide(fmt.Sprintf("target %.12s not in ig's container view", id))
	}
	return []string{"--containername", name}
}

// igContainerName returns IG's containerName for the container with the given
// full ID, or "" when IG's view does not include it.
func igContainerName(ctx context.Context, igBin string, id string) (string, error) {
	out, err := exec.CommandContext(ctx, igBin, "list-containers", "-o", "json").Output()
	if err != nil {
		return "", err
	}
	var containers []struct {
		Runtime struct {
			ContainerName string `json:"containerName"`
			ContainerID   string `json:"containerId"`
		} `json:"runtime"`
	}
	if err := json.Unmarshal(out, &containers); err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	for _, c := range containers {
		if c.Runtime.ContainerID == id {
			return c.Runtime.ContainerName, nil
		}
	}
	return "", nil
}
