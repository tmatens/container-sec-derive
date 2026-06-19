// Package runtime is csd's container-CLI seam: it selects which container
// runtime CLI (`docker` or `podman`) the inspect/history/mounts metadata calls
// shell out to. Those are the only Docker-coupled touchpoints in csd —
// `inspectEntrypoint` (image Config + RepoDigests + layer history, caps) and
// `mountDestinations` (.Mounts, fs); the eBPF observation layer is already
// runtime-agnostic (`ig` auto-detects the runtime itself, so this flag does NOT
// affect it).
//
// docker and podman are kept on the SAME commands and `--format` Go templates:
// podman ships a docker-compatible `inspect`/`history`/`image inspect` surface,
// so the only thing that varies is the binary name. If a podman smoke ever shows
// the inspect/history output diverging (issue #164), split the per-runtime
// command sets behind Resolve rather than scattering conditionals at the call
// sites. Podman support is opt-in and validated by the podman smoke lane; Docker
// remains the default + the only per-PR-tested runtime (see PLAN §Runtime
// requirements).
package runtime

import "fmt"

// Default is the runtime used when none is requested — Docker, the tested
// surface.
const Default = "docker"

// Supported lists the selectable container CLIs, in preference order.
var Supported = []string{"docker", "podman"}

// Resolve validates a requested runtime name and returns the CLI binary to
// invoke. An empty name selects Default. An unknown name is an error so the CLI
// can reject it with EX_USAGE rather than silently shelling out to a missing
// binary. docker/podman map to their own binary name; the mapping is explicit so
// adding a runtime with a differently-named CLI later is a one-line change here.
func Resolve(name string) (string, error) {
	switch name {
	case "":
		return Default, nil
	case "docker":
		return "docker", nil
	case "podman":
		return "podman", nil
	default:
		return "", fmt.Errorf("unsupported --runtime %q; supported: %v", name, Supported)
	}
}
