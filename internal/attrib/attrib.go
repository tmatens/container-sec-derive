// Package attrib is the attribution layer of the four-layer pipeline
// (Observer → Attribution → Aggregator → Formatter): the observer-agnostic
// target-selection shared by every observer. Opts carries the --container /
// --image / --all-matching selection and the init-window filter, and the
// methods here decide which container(s) an event belongs to and whether the
// selector was ambiguous.
//
// It is a foundation package: it imports internal/sidecar (for the target-mode
// constants) and internal/exit (for the typed ambiguity error), and is imported
// by the observers. It deliberately does NOT know any observer's event type —
// observers pass the runtime attribution fields (id/name/image) to
// MatchesRuntime, so a new observer reuses this selection without attrib
// depending back on it.
package attrib

import (
	"strings"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// Opts collects the knobs that control a single aggregate() pass. It exists
// because the aggregator takes a selector (container or image), a multi-replica
// opt-in, and a filter window -- four positional args was about to become five,
// which is where selection vs. behavior start to get confused at call sites.
type Opts struct {
	Container    string // --container: exact id / name / id-prefix
	Image        string // --image: image reference (may match N replicas)
	AllMatching  bool   // --all-matching: aggregate across N replicas
	InitWindowMs int    // --init-window-ms (0 disables)
}

// MatchesRuntime is the observer-agnostic target selection shared by every
// observer — their events carry the same runtime attribution fields
// (containerId / containerName / containerImageName), so the
// container/image/id-prefix selection logic lives here once.
func (o Opts) MatchesRuntime(containerID, containerName, image string) bool {
	if o.Container == "" && o.Image == "" {
		return true
	}
	if o.Container != "" {
		if containerID == o.Container || containerName == o.Container {
			return true
		}
		if len(o.Container) >= 6 && strings.HasPrefix(containerID, o.Container) {
			return true
		}
	}
	if o.Image != "" && image == o.Image {
		return true
	}
	return false
}

// Ambiguous reports whether the active selector matched more replicas than the
// user opted into aggregating. A bare --image without --all-matching is
// ambiguous; so is a --container id-prefix that matched >1 container (an exact
// id/name match yields one replica, so this only fires for a too-short prefix —
// deep-review M3). Emitting the union would be an over-permissioned profile
// (PLAN.md §Target selection). The no-selector case (whole-host / --fixture
// replay) is intentionally not ambiguous. --all-matching requires --image, so it
// only ever clears the image path.
func (o Opts) Ambiguous(replicaCount int) bool {
	if replicaCount <= 1 || o.AllMatching {
		return false
	}
	return o.Image != "" || o.Container != ""
}

// NewAmbiguousSelectionError builds the typed error for the active selector,
// naming the right flag and only offering --all-matching as a remedy for --image.
func (o Opts) NewAmbiguousSelectionError(labels []string) *exit.AmbiguousSelectionError {
	if o.Image != "" {
		return exit.NewAmbiguousSelectionError("--image", o.Image, labels, true)
	}
	return exit.NewAmbiguousSelectionError("--container", o.Container, labels, false)
}

// ModeLabel is the sidecar target.mode value for the active selector.
func (o Opts) ModeLabel() string {
	if o.Image != "" {
		if o.AllMatching {
			return sidecar.TargetModeAllMatching
		}
		return sidecar.TargetModeImage
	}
	return sidecar.TargetModeContainer
}

// Selector is the sidecar target.selector value for the active selector.
func (o Opts) Selector() string {
	if o.Image != "" {
		return o.Image
	}
	return o.Container
}
