// csd — container-sec-derive.
//
// v0.1.0-rc scope (PLAN.md §v0.1 build order): beta shipped the canonical
// sidecar + `compose` formatter + deterministic confidence rubric (with
// deferred factors). rc is landing the remaining six formatters, the
// entrypoint cross-check, `csd verify`, and the reference-image bisections.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// version is the csd release string. Set at build time via
//
//	-ldflags "-X main.version=<value>"
//
// Defaults to "dev" for plain `go build`; the release pipeline and
// the container image build inject `git describe`-style values.
// Surfaced through `csd --version` so smoke tests (image and binary)
// can assert the running build matches the published tag.
var version = "dev"

// Pinned IG release. v0.1 targets a single upstream version; MIN/MAX
// equal the pin until we've smoke-tested against a widening window.
// PLAN.md §IG version pinning defines the v1 semantics. Step 33
// promoted the version-mismatch path from warn-and-continue to a
// hard ExitSchemaMismatch (checkIGVersion below); the fixture path
// is unaffected because produceObservation short-circuits to
// aggregate() before checkIGVersion runs.
const (
	PinnedIGVersion    = "v0.51.0"
	MinIGVersion       = "v0.51.0"
	MaxTestedIGVersion = "v0.51.0"

	// TraceCapabilitiesGadget is the OCI reference ig pulls to run the
	// trace_capabilities gadget. ig v0.51.0 is fully image-based: a bare
	// "trace_capabilities" is not a valid argument to `ig run`. We tag to
	// PinnedIGVersion so the gadget image and the ig binary advance
	// together; bumping the pin means re-pulling this tag.
	TraceCapabilitiesGadget = "ghcr.io/inspektor-gadget/gadget/trace_capabilities:" + PinnedIGVersion

	// TraceOpenGadget is the OCI reference for the trace_open gadget, the
	// signal source for the v0.2 read-only-filesystem observer: it traces
	// open/openat and reports the open flags (so write-intent opens can be
	// filtered) and the symlink-resolved full path (with --paths). Tagged
	// to PinnedIGVersion in lockstep with TraceCapabilitiesGadget — bumping
	// the pin re-pulls both. See ROADMAP §v0.2 and the design in issue #77.
	TraceOpenGadget = "ghcr.io/inspektor-gadget/gadget/trace_open:" + PinnedIGVersion
)

// --observe selector values. caps is the v0.1 capability observer (default);
// fs is the v0.2 read-only-filesystem + tmpfs observer. PLAN.md §Architecture:
// observers share the four-layer pipeline, so the selector chooses the signal
// source (trace_capabilities vs trace_open) and the formatter family, not a
// separate code path per CLI.
const (
	ObserveCaps       = "caps"
	ObserveFS         = "fs"
	ObserveDevices    = "devices"
	ObservePrivileged = "privileged"
)

// capEvent is the subset of ig trace_capabilities fields we consume at
// PINNED_IG_VERSION. v0.51.0 puts process metadata under `proc` and
// container attribution under `runtime`; the string cap name is `cap`
// and the numeric form is `cap_raw` (we ignore the numeric form).
//
// Timestamp carries milliseconds. Live v0.51.0 emits two timestamp
// fields: `timestamp` as an RFC3339 string (unusable as int64), and
// `timestamp_raw` as int64 nanoseconds — the latter is what we read.
// Fixtures written before the live-schema probe use `timestamp` as an
// integer ms value; UnmarshalJSON accepts both so fixtures don't have
// to be regenerated per smoke finding.
type capEvent struct {
	Timestamp int64  `json:"-"`
	Syscall   string `json:"syscall"`
	CapName   string `json:"cap"`
	// Capable is the kretprobe verdict (PLAN.md §IG vs Tracee): true =
	// the cap was held, false = it was denied. v0.51.0 emits this on
	// every event; csd's aggregator filters to capable:true so denied
	// checks don't inflate the derived cap set. UnmarshalJSON below
	// defaults Capable to true when the field is absent so hand-rolled
	// test fixtures predating Step 19 keep working unchanged.
	Capable bool `json:"-"`
	Proc    struct {
		Comm string `json:"comm"`
		Pid  int    `json:"pid"`
	} `json:"proc"`
	Runtime struct {
		ContainerID    string `json:"containerId"`
		ContainerName  string `json:"containerName"`
		ContainerImage string `json:"containerImageName"`
		RuntimeName    string `json:"runtimeName"`
	} `json:"runtime"`
}

func (e *capEvent) UnmarshalJSON(data []byte) error {
	type procT struct {
		Comm string `json:"comm"`
		Pid  int    `json:"pid"`
	}
	type runtimeT struct {
		ContainerID    string `json:"containerId"`
		ContainerName  string `json:"containerName"`
		ContainerImage string `json:"containerImageName"`
		RuntimeName    string `json:"runtimeName"`
	}
	var wire struct {
		Timestamp    json.RawMessage `json:"timestamp"`
		TimestampRaw int64           `json:"timestamp_raw"`
		Syscall      string          `json:"syscall"`
		CapName      string          `json:"cap"`
		// *bool so we can distinguish "absent" from "false". Absent
		// defaults to true (lenient) so legacy hand-rolled fixtures
		// without a `capable` field don't get silently filtered out;
		// pinned ig v0.51.0 always emits the field, so the live path
		// gets exact verdict semantics regardless.
		Capable *bool    `json:"capable"`
		Proc    procT    `json:"proc"`
		Runtime runtimeT `json:"runtime"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	e.Syscall = wire.Syscall
	e.CapName = wire.CapName
	if wire.Capable == nil {
		e.Capable = true
	} else {
		e.Capable = *wire.Capable
	}
	e.Proc = wire.Proc
	e.Runtime = wire.Runtime
	switch {
	case wire.TimestampRaw != 0:
		// Live v0.51.0: nanoseconds → milliseconds.
		e.Timestamp = wire.TimestampRaw / 1_000_000
	case len(wire.Timestamp) > 0:
		// Fixture fallback: bare integer ms. RFC3339 strings from live
		// ig also land here but fail int decode and are ignored — the
		// ns value from timestamp_raw is authoritative on live runs.
		var n int64
		_ = json.Unmarshal(wire.Timestamp, &n)
		e.Timestamp = n
	}
	return nil
}

// igLostSamplesRE matches ig's ringbuf-loss stderr warnings. v0.51.0
// emits these as logrus-formatted lines rather than typed stdout
// events; parsing them is the only way to surface drop counts on
// real hosts. PLAN.md §Event-loss reporting.
var igLostSamplesRE = regexp.MustCompile(`lost (\d+) samples`)

// aggregateOpts collects the knobs that control a single aggregate()
// pass. It exists because the aggregator now takes a selector (container
// or image), a multi-replica opt-in, and a filter window -- four
// positional args was about to become five, which is where selection
// vs. behavior start to get confused at call sites.
type aggregateOpts struct {
	Container    string // --container: exact id / name / id-prefix
	Image        string // --image: image reference (may match N replicas)
	AllMatching  bool   // --all-matching: aggregate across N replicas
	InitWindowMs int    // --init-window-ms (0 disables)
}

func (o aggregateOpts) matches(ev capEvent) bool {
	return o.matchesRuntime(ev.Runtime.ContainerID, ev.Runtime.ContainerName, ev.Runtime.ContainerImage)
}

// matchesRuntime is the observer-agnostic target selection shared by the
// capability and file-write observers — their events carry the same runtime
// attribution fields (containerId / containerName / containerImageName), so
// the container/image/id-prefix selection logic lives here once.
func (o aggregateOpts) matchesRuntime(containerID, containerName, image string) bool {
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

func (o aggregateOpts) modeLabel() string {
	if o.Image != "" {
		if o.AllMatching {
			return TargetModeAllMatching
		}
		return TargetModeImage
	}
	return TargetModeContainer
}

func (o aggregateOpts) selector() string {
	if o.Image != "" {
		return o.Image
	}
	return o.Container
}

func main() {
	err := run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "csd:", err)
	}
	os.Exit(exitCodeFor(err))
}

func run(args []string, stdout, stderr io.Writer) error {
	// Subcommand dispatch. v0.1 has two explicit subcommands (`observe`,
	// `verify`); the no-arg / flags-only form (`csd --container x`) is
	// also accepted for the observe path so docs that omit the
	// subcommand still work. `observe` is dispatched by stripping the
	// keyword and falling through to the same flag parser the bare form
	// uses -- otherwise flag.Parse stops at the positional and the
	// trailing flags never bind. If a future subcommand is added,
	// mirror this shape: peek at args[0], dispatch, fall through on
	// no match.
	if len(args) > 0 && args[0] == "verify" {
		return runVerify(args[1:], stdout, stderr)
	}
	// --version short-circuits all flag parsing; `csd --version` and
	// `csd version` both work. Image/binary smoke tests parse this
	// string to assert the running build matches the published tag.
	if len(args) > 0 && (args[0] == "--version" || args[0] == "-version" || args[0] == "version") {
		fmt.Fprintf(stdout, "csd %s\n", version)
		return nil
	}
	if len(args) > 0 && args[0] == "observe" {
		args = args[1:]
	}

	fs := flag.NewFlagSet("csd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		container        = fs.String("container", "", "target container id or name (mutually exclusive with --image)")
		image            = fs.String("image", "", "select containers by image reference (errors if >1 match without --all-matching)")
		allMatching      = fs.Bool("all-matching", false, "aggregate across all replicas matching --image")
		observe          = fs.String("observe", ObserveCaps, "observer to run: caps (Linux capabilities), fs (read-only filesystem + tmpfs), devices (device decomposition), or privileged (drop privileged: true → cap_add + devices)")
		mountsFixture    = fs.String("mounts-fixture", "", "fs observer only: read container mount destinations from this `docker inspect` .Mounts JSON instead of running docker inspect")
		deviceFixture    = fs.String("device-fixture", "", "privileged observer only: read the trace_open NDJSON for the devices half from this file (the --fixture file supplies the trace_capabilities half)")
		fixture          = fs.String("fixture", "", "read ig-format NDJSON from this file instead of spawning ig")
		fixtureErr       = fs.String("fixture-stderr", "", "fixture-mode only: file of ig stderr lines; drops parsed as if piped from live ig")
		inspectFixture   = fs.String("inspect-fixture", "", "read pre-captured image-inspection JSON from this file instead of running `docker inspect`")
		duration         = fs.Duration("duration", 30*time.Second, "observation window (ignored in --fixture mode)")
		igBin            = fs.String("ig", "ig", "path to the ig binary")
		initWindowMs     = fs.Int("init-window-ms", 500, "drop capability events observed within this many ms of the first matching event (0 disables)")
		outPath          = fs.String("out", "", "write canonical JSON evidence sidecar to this file (stdout still prints the chosen --format)")
		format           = fs.String("format", FormatCompose, "output format for stdout (implemented: compose, compose-patch, compose-lint-profile, docker-run, json, k8s, oci)")
		allowExploratory = fs.Bool("allow-exploratory", false, "compose-lint-profile only: emit under exploratory: even when the acceptance contract is not met")
		workload         = fs.String("workload", "", "path to the user-supplied workload script that exercised the container; recorded on the sidecar and required by the compose-lint-profile gate")
		composeIn        = fs.String("compose-in", "", "compose-patch only: path to the user's compose file to diff against")
		composeService   = fs.String("service", "", "compose-patch only: name of the service under services: whose cap_drop/cap_add to rewrite")
	)
	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError surfaces -h/--help as ErrHelp and bad
		// flags as parse errors. CI integrators want both as EX_USAGE.
		return wrapCoded(ExitUsage, err)
	}

	if *container != "" && *image != "" {
		return codedErrorf(ExitUsage, "--container and --image are mutually exclusive")
	}
	if *allMatching && *image == "" {
		return codedErrorf(ExitUsage, "--all-matching requires --image")
	}
	if *fixture == "" && *container == "" && *image == "" {
		return codedErrorf(ExitUsage, "one of --container or --image is required (or pass --fixture <file> to read pre-captured events)")
	}
	switch *format {
	case FormatCompose, FormatComposePatch, FormatComposeLintEntry, FormatDockerRun, FormatJSON, FormatK8s, FormatOCI:
		// implemented
	default:
		return codedErrorf(ExitUsage, "--format %q not recognized; supported: %s, %s, %s, %s, %s, %s, %s", *format, FormatCompose, FormatComposePatch, FormatComposeLintEntry, FormatDockerRun, FormatJSON, FormatK8s, FormatOCI)
	}
	switch *observe {
	case ObserveCaps, ObserveFS, ObserveDevices, ObservePrivileged:
		// recognized
	default:
		return codedErrorf(ExitUsage, "--observe %q not recognized; supported: %s, %s, %s, %s", *observe, ObserveCaps, ObserveFS, ObserveDevices, ObservePrivileged)
	}
	if *observe != ObserveFS && *mountsFixture != "" {
		return codedErrorf(ExitUsage, "--mounts-fixture is only meaningful with --observe %s", ObserveFS)
	}
	if *observe != ObservePrivileged && *deviceFixture != "" {
		return codedErrorf(ExitUsage, "--device-fixture is only meaningful with --observe %s", ObservePrivileged)
	}
	// Workload is recorded on the sidecar and surfaced as a confidence factor
	// (both observers); the compose-lint contribution gate also requires the
	// file to be readable. Validate before either observe path so a typo'd
	// path fails fast (EX_USAGE) rather than after a full observation window.
	if *workload != "" {
		if _, err := os.Stat(*workload); err != nil {
			return wrapCoded(ExitUsage, fmt.Errorf("--workload %q: %w", *workload, err))
		}
	}
	// The v0.2 fs observer is a distinct signal source (trace_open) producing a
	// read_only/tmpfs recommendation in the Sidecar's fs section, so it takes
	// its own produce→format path and returns before the capability formatter
	// switch. PR-A wires the JSON sidecar (+ --out, --workload, confidence,
	// drop abort) and the compose formatter; the remaining five formatters are
	// the PR-B follow-on, hence the format guard below.
	if *observe == ObserveFS {
		// All seven formatters are implemented for fs. compose-patch needs
		// --compose-in/--service (validated below, shared with the cap path);
		// compose-lint-profile honors --allow-exploratory.
		if *format == FormatComposePatch {
			if *composeIn == "" || *composeService == "" {
				return codedErrorf(ExitUsage, "--format %s requires both --compose-in <path> and --service <name>", FormatComposePatch)
			}
			if _, statErr := os.Stat(*composeIn); statErr != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("--compose-in %q: %w", *composeIn, statErr))
			}
		} else if *composeIn != "" || *composeService != "" {
			return codedErrorf(ExitUsage, "--compose-in / --service are only meaningful with --format %s", FormatComposePatch)
		}
		if *allowExploratory && *format != FormatComposeLintEntry {
			return codedErrorf(ExitUsage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
		}
		s, err := produceFSObservation(fsPipelineOpts{
			AggregateOpts: aggregateOpts{
				Container:   *container,
				Image:       *image,
				AllMatching: *allMatching,
			},
			Fixture:       *fixture,
			MountsFixture: *mountsFixture,
			IGBin:         *igBin,
			Duration:      *duration,
			Workload:      *workload,
		}, stderr)
		if err != nil {
			return err
		}
		switch *format {
		case FormatCompose:
			if err := writeFSCompose(stdout, *s.FSRecommendation); err != nil {
				return fmt.Errorf("write fs compose: %w", err)
			}
		case FormatJSON:
			if err := writeJSON(stdout, s); err != nil {
				return fmt.Errorf("write json: %w", err)
			}
		case FormatDockerRun:
			if err := writeFSDockerRun(stdout, *s.FSRecommendation); err != nil {
				return fmt.Errorf("write fs docker-run: %w", err)
			}
		case FormatK8s:
			if err := writeFSK8s(stdout, *s.FSRecommendation); err != nil {
				return fmt.Errorf("write fs k8s: %w", err)
			}
		case FormatOCI:
			if err := writeFSOCI(stdout, *s.FSRecommendation); err != nil {
				return fmt.Errorf("write fs oci: %w", err)
			}
		case FormatComposePatch:
			raw, readErr := os.ReadFile(*composeIn)
			if readErr != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("read --compose-in %q: %w", *composeIn, readErr))
			}
			if err := writeFSComposePatch(stdout, *s.FSRecommendation, raw, *composeIn, *composeService); err != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("write fs compose-patch: %w", err))
			}
		case FormatComposeLintEntry:
			if err := writeFSComposeLintProfile(stdout, s, *allowExploratory); err != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("write fs compose-lint-profile: %w", err))
			}
		}
		if *outPath != "" {
			if err := writeSidecar(s, *outPath); err != nil {
				return fmt.Errorf("write sidecar: %w", err)
			}
		}
		if s.TraceHealth.DropRate >= DropRateAbort {
			return codedErrorf(ExitDropRateExcessive,
				"trace_health drop rate %.4f >= %.2f; profile not trustworthy (events_recorded=%d events_dropped=%d)",
				s.TraceHealth.DropRate, DropRateAbort,
				s.TraceHealth.EventsRecorded, s.TraceHealth.EventsDropped,
			)
		}
		return nil
	}
	// The v0.3 device-decomposition observer is a third signal source
	// (trace_open filtered to non-default /dev nodes) producing a devices: +
	// derived-cap recommendation in the Sidecar's device section, so it takes
	// its own produce→format path and returns before the capability formatter
	// switch. This PR wires the JSON sidecar (the canonical evidence artifact)
	// and the compose formatter; the remaining five formatters are follow-on
	// PRs, hence the format guard.
	if *observe == ObserveDevices {
		// All seven formatters are now implemented for devices. compose-patch
		// needs --compose-in/--service (validated below, shared shape with the
		// cap/fs paths); compose-lint-profile honors --allow-exploratory.
		if *format == FormatComposePatch {
			if *composeIn == "" || *composeService == "" {
				return codedErrorf(ExitUsage, "--format %s requires both --compose-in <path> and --service <name>", FormatComposePatch)
			}
			if _, statErr := os.Stat(*composeIn); statErr != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("--compose-in %q: %w", *composeIn, statErr))
			}
		} else if *composeIn != "" || *composeService != "" {
			return codedErrorf(ExitUsage, "--compose-in / --service are only meaningful with --format %s", FormatComposePatch)
		}
		if *allowExploratory && *format != FormatComposeLintEntry {
			return codedErrorf(ExitUsage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
		}
		s, err := produceDeviceObservation(devicePipelineOpts{
			AggregateOpts: aggregateOpts{
				Container:   *container,
				Image:       *image,
				AllMatching: *allMatching,
			},
			Fixture:  *fixture,
			IGBin:    *igBin,
			Duration: *duration,
			Workload: *workload,
		}, stderr)
		if err != nil {
			return err
		}
		switch *format {
		case FormatCompose:
			if err := writeDeviceCompose(stdout, *s.DeviceRecommendation); err != nil {
				return fmt.Errorf("write device compose: %w", err)
			}
		case FormatJSON:
			if err := writeJSON(stdout, s); err != nil {
				return fmt.Errorf("write json: %w", err)
			}
		case FormatDockerRun:
			if err := writeDeviceDockerRun(stdout, *s.DeviceRecommendation); err != nil {
				return fmt.Errorf("write device docker-run: %w", err)
			}
		case FormatK8s:
			if err := writeDeviceK8s(stdout, *s.DeviceRecommendation); err != nil {
				return fmt.Errorf("write device k8s: %w", err)
			}
		case FormatOCI:
			if err := writeDeviceOCI(stdout, *s.DeviceRecommendation); err != nil {
				return fmt.Errorf("write device oci: %w", err)
			}
		case FormatComposePatch:
			raw, readErr := os.ReadFile(*composeIn)
			if readErr != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("read --compose-in %q: %w", *composeIn, readErr))
			}
			if err := writeDeviceComposePatch(stdout, *s.DeviceRecommendation, raw, *composeIn, *composeService); err != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("write device compose-patch: %w", err))
			}
		case FormatComposeLintEntry:
			if err := writeDeviceComposeLintProfile(stdout, s, *allowExploratory); err != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("write device compose-lint-profile: %w", err))
			}
		}
		if *outPath != "" {
			if err := writeSidecar(s, *outPath); err != nil {
				return fmt.Errorf("write sidecar: %w", err)
			}
		}
		if s.TraceHealth.DropRate >= DropRateAbort {
			return codedErrorf(ExitDropRateExcessive,
				"trace_health drop rate %.4f >= %.2f; profile not trustworthy (events_recorded=%d events_dropped=%d)",
				s.TraceHealth.DropRate, DropRateAbort,
				s.TraceHealth.EventsRecorded, s.TraceHealth.EventsDropped,
			)
		}
		return nil
	}
	// The v0.3 privileged-mode decomposition composes the capability and device
	// observers (two concurrent gadget streams live; --fixture + --device-fixture
	// hermetically) and emits the minimum non-privileged equivalent. It takes its
	// own produce→format path and returns before the capability formatter switch.
	// This PR wires the JSON sidecar and the compose formatter; the remaining
	// five formatters are the follow-on PR, hence the format guard.
	if *observe == ObservePrivileged {
		// All seven formatters are implemented for privileged. compose-patch
		// needs --compose-in/--service; compose-lint-profile honors
		// --allow-exploratory (shared shape with the cap/fs/device paths).
		if *format == FormatComposePatch {
			if *composeIn == "" || *composeService == "" {
				return codedErrorf(ExitUsage, "--format %s requires both --compose-in <path> and --service <name>", FormatComposePatch)
			}
			if _, statErr := os.Stat(*composeIn); statErr != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("--compose-in %q: %w", *composeIn, statErr))
			}
		} else if *composeIn != "" || *composeService != "" {
			return codedErrorf(ExitUsage, "--compose-in / --service are only meaningful with --format %s", FormatComposePatch)
		}
		if *allowExploratory && *format != FormatComposeLintEntry {
			return codedErrorf(ExitUsage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
		}
		s, err := producePrivilegedObservation(privilegedPipelineOpts{
			AggregateOpts: aggregateOpts{
				Container:    *container,
				Image:        *image,
				AllMatching:  *allMatching,
				InitWindowMs: *initWindowMs,
			},
			Fixture:        *fixture,
			DeviceFixture:  *deviceFixture,
			FixtureStderr:  *fixtureErr,
			InspectFixture: *inspectFixture,
			IGBin:          *igBin,
			Duration:       *duration,
			Workload:       *workload,
		}, stderr)
		if err != nil {
			return err
		}
		switch *format {
		case FormatCompose:
			if err := writePrivilegedCompose(stdout, s); err != nil {
				return fmt.Errorf("write privileged compose: %w", err)
			}
		case FormatJSON:
			if err := writeJSON(stdout, s); err != nil {
				return fmt.Errorf("write json: %w", err)
			}
		case FormatDockerRun:
			if err := writePrivilegedDockerRun(stdout, s); err != nil {
				return fmt.Errorf("write privileged docker-run: %w", err)
			}
		case FormatK8s:
			if err := writePrivilegedK8s(stdout, s); err != nil {
				return fmt.Errorf("write privileged k8s: %w", err)
			}
		case FormatOCI:
			if err := writePrivilegedOCI(stdout, s); err != nil {
				return fmt.Errorf("write privileged oci: %w", err)
			}
		case FormatComposePatch:
			raw, readErr := os.ReadFile(*composeIn)
			if readErr != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("read --compose-in %q: %w", *composeIn, readErr))
			}
			if err := writePrivilegedComposePatch(stdout, s, raw, *composeIn, *composeService); err != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("write privileged compose-patch: %w", err))
			}
		case FormatComposeLintEntry:
			if err := writePrivilegedComposeLintProfile(stdout, s, *allowExploratory); err != nil {
				return wrapCoded(ExitUsage, fmt.Errorf("write privileged compose-lint-profile: %w", err))
			}
		}
		if *outPath != "" {
			if err := writeSidecar(s, *outPath); err != nil {
				return fmt.Errorf("write sidecar: %w", err)
			}
		}
		emitAdvisoryWarnings(s, stderr)
		if s.TraceHealth.DropRate >= DropRateAbort {
			return codedErrorf(ExitDropRateExcessive,
				"trace_health drop rate %.4f >= %.2f; profile not trustworthy (events_recorded=%d events_dropped=%d)",
				s.TraceHealth.DropRate, DropRateAbort,
				s.TraceHealth.EventsRecorded, s.TraceHealth.EventsDropped,
			)
		}
		return nil
	}
	if *allowExploratory && *format != FormatComposeLintEntry {
		return codedErrorf(ExitUsage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
	}
	// compose-patch needs both --compose-in and --service; reject the
	// flags elsewhere so a future user doesn't believe they have an
	// effect with another formatter.
	if *format == FormatComposePatch {
		if *composeIn == "" || *composeService == "" {
			return codedErrorf(ExitUsage, "--format %s requires both --compose-in <path> and --service <name>", FormatComposePatch)
		}
		if _, err := os.Stat(*composeIn); err != nil {
			return wrapCoded(ExitUsage, fmt.Errorf("--compose-in %q: %w", *composeIn, err))
		}
	} else if *composeIn != "" || *composeService != "" {
		return codedErrorf(ExitUsage, "--compose-in / --service are only meaningful with --format %s", FormatComposePatch)
	}

	s, err := produceObservation(observePipelineOpts{
		AggregateOpts: aggregateOpts{
			Container:    *container,
			Image:        *image,
			AllMatching:  *allMatching,
			InitWindowMs: *initWindowMs,
		},
		Fixture:        *fixture,
		FixtureStderr:  *fixtureErr,
		InspectFixture: *inspectFixture,
		IGBin:          *igBin,
		Duration:       *duration,
		Workload:       *workload,
	}, stderr)
	if err != nil {
		return err
	}
	switch *format {
	case FormatCompose:
		if err := writeCompose(stdout, s); err != nil {
			return fmt.Errorf("write compose: %w", err)
		}
	case FormatComposePatch:
		raw, readErr := os.ReadFile(*composeIn)
		if readErr != nil {
			return wrapCoded(ExitUsage, fmt.Errorf("read --compose-in %q: %w", *composeIn, readErr))
		}
		if err := writeComposePatch(stdout, s, raw, *composeIn, *composeService); err != nil {
			// Service-not-found / services-block-missing are usage
			// errors: the user pointed at a file that can't host the
			// patch, not a runtime failure of csd.
			return wrapCoded(ExitUsage, fmt.Errorf("write compose-patch: %w", err))
		}
	case FormatDockerRun:
		if err := writeDockerRun(stdout, s); err != nil {
			return fmt.Errorf("write docker-run: %w", err)
		}
	case FormatJSON:
		if err := writeJSON(stdout, s); err != nil {
			return fmt.Errorf("write json: %w", err)
		}
	case FormatK8s:
		if err := writeK8s(stdout, s); err != nil {
			return fmt.Errorf("write k8s: %w", err)
		}
	case FormatOCI:
		if err := writeOCI(stdout, s); err != nil {
			return fmt.Errorf("write oci: %w", err)
		}
	case FormatComposeLintEntry:
		if err := writeComposeLintProfile(stdout, s, *allowExploratory); err != nil {
			// Contract-not-met is a usage-class failure: the user asked
			// for a contribution-ready profile and the artifact didn't
			// clear the bar. Surface as EX_USAGE so CI pipelines catch
			// it rather than quietly accepting a silently-empty stdout.
			return wrapCoded(ExitUsage, fmt.Errorf("write compose-lint-profile: %w", err))
		}
	}

	// Sidecar is written before the drop-rate abort so CI integrators
	// still get the artifact-with-caveat that PLAN.md §Exit codes
	// promises for code 21.
	if *outPath != "" {
		if err := writeSidecar(s, *outPath); err != nil {
			return fmt.Errorf("write sidecar: %w", err)
		}
	}

	emitAdvisoryWarnings(s, stderr)

	// Drop rate >= 10% is "artifact-with-caveat" per PLAN.md §Exit codes:
	// caps have already been printed; the nonzero exit is what tells CI
	// the profile isn't trustworthy.
	if s.TraceHealth.DropRate >= DropRateAbort {
		return codedErrorf(ExitDropRateExcessive,
			"trace_health drop rate %.4f >= %.2f; profile not trustworthy (events_recorded=%d events_dropped=%d)",
			s.TraceHealth.DropRate, DropRateAbort,
			s.TraceHealth.EventsRecorded, s.TraceHealth.EventsDropped,
		)
	}
	return nil
}

// emitAdvisoryWarnings surfaces sub-abort signals the aggregator already
// records but didn't previously make user-visible. PLAN.md §v0.1 build
// order rc bullet 9: replica disagreement and sub-10% drop rate are
// recorded on the sidecar but only useful if reviewers can see them
// without reading the JSON. Both are non-fatal (the ≥10% drop abort
// stays); silent stderr is the cheapest path to making them obvious.
func emitAdvisoryWarnings(s *Sidecar, stderr io.Writer) {
	if stderr == nil {
		return
	}
	if s.TraceHealth.DropRate > 0 && s.TraceHealth.DropRate < DropRateAbort {
		fmt.Fprintf(stderr,
			"csd: warning: trace_health drop_rate %.4f (%d dropped / %d recorded); below %.2f abort threshold but profile may be incomplete\n",
			s.TraceHealth.DropRate, s.TraceHealth.EventsDropped, s.TraceHealth.EventsRecorded, DropRateAbort,
		)
	}
	if len(s.Target.ReplicaCapDisagreement) > 0 {
		fmt.Fprintf(stderr,
			"csd: warning: replicas disagree on %d cap(s) [%s]; --all-matching produced a union profile that no single replica required\n",
			len(s.Target.ReplicaCapDisagreement),
			strings.Join(s.Target.ReplicaCapDisagreement, ", "),
		)
	}
}

// noteWSL2IfDetected emits a one-line stderr advisory pointing at
// docs/wsl2.md when the host kernel string identifies as WSL2. PLAN.md
// §Platform support: WSL2 + Docker Desktop is nominally supported but
// kernel coverage and BTF availability vary across builds; the note
// directs the user to the per-image smoke matrix and known-issues list
// before they trust an observation. Live observe path only -- fixture
// replay is host-agnostic.
func noteWSL2IfDetected(stderr io.Writer) {
	if stderr == nil {
		return
	}
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return
	}
	if !looksLikeWSL2(string(data)) {
		return
	}
	fmt.Fprintln(stderr, "csd: note: WSL2 host detected; see docs/wsl2.md for known-good kernel versions and BTF/Docker Desktop notes")
}

// looksLikeWSL2 returns true when the /proc/version contents match
// either of the two markers WSL2 kernels carry. Both forms have been
// observed across the Microsoft kernel branches: the older lower-case
// "microsoft" tag and the explicit "WSL2" tag on the 5.15+ images.
func looksLikeWSL2(procVersion string) bool {
	lower := strings.ToLower(procVersion)
	return strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl2")
}

// observePipelineOpts bundles every input the fixture-or-live observe
// pipeline takes. Step 23 introduced the helper so `csd verify`'s
// run-mode can produce the verify-time observation without duplicating
// the observe→finalise→cross-check→confidence sequence from run().
//
// Composition: AggregateOpts carries the per-event-stream knobs
// (container/image selectors, init-window). The remaining fields are
// the wrapping concerns (where the events come from, where digests
// come from, how long the live window runs, the workload script
// recorded on the sidecar).
type observePipelineOpts struct {
	AggregateOpts  aggregateOpts
	Fixture        string
	FixtureStderr  string
	InspectFixture string
	IGBin          string
	Duration       time.Duration
	Workload       string
}

// produceObservation runs the fixture-or-live observe path end-to-end
// and returns a fully populated Sidecar with confidence already scored.
// Mirrors the body of run() prior to the formatter switch; both `run`
// (default observe path) and `runVerify` (Step 23 run-mode) call it so
// any future fix to the pipeline lands in one place.
//
// Errors that the run path translated to typed exit codes are
// translated here: ambiguous-selection becomes ExitTargetAmbiguous,
// ig-missing flows through observe()'s wrapped error verbatim. Drop-
// rate abort is NOT applied here -- callers may want to emit the
// formatted artifact (run) or the verify result (runVerify) before
// surfacing the abort, and centralising that here would force a flag
// on this helper that neither caller needs.
func produceObservation(opts observePipelineOpts, stderr io.Writer) (*Sidecar, error) {
	observedAt := time.Now().UTC()

	var (
		s   *Sidecar
		err error
	)
	if opts.Fixture != "" {
		src, openErr := os.Open(opts.Fixture)
		if openErr != nil {
			return nil, fmt.Errorf("open fixture: %w", openErr)
		}
		defer src.Close()
		s, err = aggregate(src, opts.AggregateOpts)
		// Fixture mode: duration is unknown, so leave DurationSeconds=0
		// (computeConfidence treats 0 as "not measured" and skips the
		// soft-floor check).
		if err == nil && s != nil && opts.FixtureStderr != "" {
			errSrc, openErrErr := os.Open(opts.FixtureStderr)
			if openErrErr != nil {
				return nil, fmt.Errorf("open fixture-stderr: %w", openErrErr)
			}
			s.TraceHealth.EventsDropped = parseIGStderr(errSrc, nil)
			errSrc.Close()
		}
	} else {
		noteWSL2IfDetected(stderr)
		if verr := checkIGVersion(opts.IGBin, stderr); verr != nil {
			return nil, verr
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()
		s, err = observe(ctx, opts.IGBin, opts.AggregateOpts, stderr)
		if s != nil {
			s.DurationSeconds = int(opts.Duration.Seconds())
		}
	}
	if s != nil {
		finaliseTraceHealth(&s.TraceHealth)
	}
	if err != nil {
		var amb *ambiguousSelectionError
		if errors.As(err, &amb) {
			return nil, wrapCoded(ExitTargetAmbiguous, err)
		}
		return nil, err
	}

	s.ObservedAt = observedAt
	s.Workload = opts.Workload
	applyEntrypointCrossCheck(s, opts.InspectFixture, opts.Fixture != "", stderr)
	computeConfidence(s)
	return s, nil
}

// observe spawns `ig run trace_capabilities --output json` and aggregates
// events for the lifetime of ctx. ig's stderr is tee'd through
// parseIGStderr so the ringbuf-loss counter (v0.51.0 emits these as
// stderr warnings, not typed stdout events) lands on the sidecar.
func observe(ctx context.Context, igBin string, opts aggregateOpts, stderrSink io.Writer) (*Sidecar, error) {
	cmd := exec.CommandContext(ctx, igBin, "run", TraceCapabilitiesGadget, "--output", "json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		if isIGMissing(err) {
			return nil, wrapCoded(ExitIGMissing, fmt.Errorf("ig binary %q not available: %w", igBin, err))
		}
		return nil, fmt.Errorf("start %s: %w", igBin, err)
	}

	var (
		wg     sync.WaitGroup
		lost   int
		lostMu sync.Mutex
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		n := parseIGStderr(stderrPipe, stderrSink)
		lostMu.Lock()
		lost = n
		lostMu.Unlock()
	}()

	s, aggErr := aggregate(stdout, opts)
	// Wait for ig to exit. A context-cancel kill is the normal termination
	// path for the timed observation window, so we don't propagate that as
	// an error.
	waitErr := cmd.Wait()
	wg.Wait()
	if s != nil {
		s.TraceHealth.EventsDropped = lost
	}
	if aggErr != nil && !errors.Is(aggErr, io.EOF) {
		return nil, aggErr
	}
	if waitErr != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("ig exited: %w", waitErr)
	}
	return s, nil
}

// parseIGStderr scans ig's stderr stream for ringbuf-loss warnings
// of the form `lost N samples` (ig v0.51.0 format) and returns the
// cumulative total. Every line is echoed to sink so operators still
// see ig's diagnostics; passing nil for sink silences passthrough.
func parseIGStderr(r io.Reader, sink io.Writer) int {
	total := 0
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	for scan.Scan() {
		line := scan.Bytes()
		if sink != nil {
			fmt.Fprintln(sink, string(line))
		}
		m := igLostSamplesRE.FindSubmatch(line)
		if len(m) == 2 {
			if n, err := strconv.Atoi(string(m[1])); err == nil {
				total += n
			}
		}
	}
	return total
}

// finaliseTraceHealth computes DropRate once both sides of the ratio
// are known. recorded is the count of events csd parsed; dropped is
// ig's stderr-reported loss. Ratio is dropped / recorded to preserve
// the pre-Step-11 rubric thresholds; recomputing against the total
// population (dropped + recorded) would shift every threshold and is
// out of scope for the parser realignment.
func finaliseTraceHealth(th *TraceHealth) {
	if th.EventsRecorded > 0 {
		th.DropRate = float64(th.EventsDropped) / float64(th.EventsRecorded)
	} else if th.EventsDropped > 0 {
		// All-dropped-no-recorded is a pathological case we can still
		// report as "everything lost". Without this branch a 0-record
		// run with losses would look clean.
		th.DropRate = 1.0
	}
}

// checkIGVersion runs `ig version` and returns ExitSchemaMismatch when
// the detected release is outside [MinIGVersion, MaxTestedIGVersion].
// ig v0.51.0 does not support --output json on `version`; the
// subcommand emits a single plain-text line like "v0.51.0". We take
// the first whitespace-delimited token so future ig releases that
// add trailing metadata still parse.
//
// Step 33 promotes this to a hard SchemaMismatch exit per PLAN.md
// §IG version pinning. Phase A (Steps 11.1..32) was warn-and-continue
// so we'd learn about drift without breaking fixture-only users; the
// fixture path doesn't reach this function (produceObservation
// short-circuits to aggregate() before the version check), so the
// hard-fail only affects live observe.
//
// Failures of `ig version` itself (binary missing, exec error) are
// NOT treated as SchemaMismatch — observe() will surface ExitIGMissing
// for the same condition. Returning nil here keeps the version-check
// out of that error's blast radius.
func checkIGVersion(igBin string, stderr io.Writer) error {
	out, err := exec.Command(igBin, "version").Output()
	if err != nil {
		if stderr != nil {
			fmt.Fprintf(stderr, "csd: ig version check skipped: %v\n", err)
		}
		return nil
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return nil
	}
	detected := fields[0]
	if detected == "" {
		return nil
	}
	if detected != PinnedIGVersion {
		return codedErrorf(ExitSchemaMismatch,
			"ig %s detected, PINNED_IG_VERSION=%s (tested window %s..%s); refusing to parse — see PLAN.md §IG version pinning",
			detected, PinnedIGVersion, MinIGVersion, MaxTestedIGVersion,
		)
	}
	return nil
}

// replicaState accumulates per-replica data as aggregate() streams events.
// Replica identity is the container id (falling back to name when id is
// empty, as happens in hand-authored test fixtures). Under live BPF this
// will be cgroup id -- see PLAN.md §Target selection for the attribution
// contract. Init-window filtering is per-replica because each replica has
// its own startup phase.
type replicaState struct {
	seen       map[string]*capStats
	comms      map[string]struct{} // post-init-window comms; feeds confidence rubric
	firstTsMs  int64
	firstSeen  bool
	suppressed int
	eventCount int
	sampleName string // for ambiguity-error messages
	image      string // first observed ev.Runtime.ContainerImage; populates Sidecar.Image when --image not set
}

// capStats collapses N raw events for one capability into audit-ready
// numbers. PLAN.md §Output schema requires event_count + first/last offset
// + comm_samples so reviewers can trace a cap back to the workload phase
// that needed it. Used per-replica (for PerReplicaCaps book-keeping) and
// merged into a single union stats map that populates Sidecar.Capabilities.
type capStats struct {
	eventCount  int
	firstTsMs   int64
	lastTsMs    int64
	hasTs       bool
	commSamples map[string]struct{}
}

func newCapStats() *capStats {
	return &capStats{commSamples: map[string]struct{}{}}
}

func (c *capStats) observe(tsMs int64, comm string) {
	c.eventCount++
	if !c.hasTs || tsMs < c.firstTsMs {
		c.firstTsMs = tsMs
	}
	if tsMs > c.lastTsMs {
		c.lastTsMs = tsMs
	}
	c.hasTs = true
	if comm != "" {
		c.commSamples[comm] = struct{}{}
	}
}

// aggregate reads NDJSON events from r, filters via opts.matches(), and
// returns a *Sidecar populated with per-replica event counts, per-replica
// cap sets, cross-replica cap disagreement, and the union cap set.
//
// With --image but without --all-matching, matching more than one replica
// is an error (PLAN.md §Target selection): the tool refuses to pretend
// every replica needs every cap.
//
// opts.InitWindowMs drops events observed within that many milliseconds
// of each replica's first matching event, reducing runc / ld.so init
// noise. 0 disables. Suppressed-event count is summed across replicas
// onto Target.InitWindowSuppressed.
//
// Timestamps are assumed to be milliseconds (fixture convention, matching
// `ig run trace_capabilities --output json` at the pinned release).
// Revisit if Step 11's IG version pin exposes a different unit.
func aggregate(r io.Reader, opts aggregateOpts) (*Sidecar, error) {
	replicas := map[string]*replicaState{}
	capUnion := map[string]*capStats{}
	var recorded int
	var globalFirstTsMs int64
	globalFirstSeen := false
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	for scan.Scan() {
		line := scan.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev capEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			// Skip malformed lines rather than abort the observation
			// window. Real IG output can include non-event diagnostic
			// lines on some versions.
			continue
		}
		if !opts.matches(ev) {
			continue
		}
		recorded++
		// Capable=false events are kretprobe-recorded denials: the
		// kernel asked, the LSM said no. PLAN.md §IG vs Tracee — we
		// only want held caps in the derived set. Counted toward
		// events_recorded so drop_rate's denominator reflects every
		// real ig sample we parsed.
		if !ev.Capable {
			continue
		}
		rid := ev.Runtime.ContainerID
		if rid == "" {
			rid = ev.Runtime.ContainerName
		}
		st, ok := replicas[rid]
		if !ok {
			st = &replicaState{
				seen:       map[string]*capStats{},
				comms:      map[string]struct{}{},
				sampleName: ev.Runtime.ContainerName,
				image:      ev.Runtime.ContainerImage,
			}
			replicas[rid] = st
		}
		st.eventCount++
		if !st.firstSeen {
			st.firstTsMs = ev.Timestamp
			st.firstSeen = true
		}
		// Comm-aware init filter (PLAN.md §Foot-guns "Init-process noise"):
		// runc:[*] events are container-init capability checks regardless
		// of when they fire. Step 11.1 follow-up (iii) saw runc:[2:INIT]
		// events leak past the 500ms time window on real postgres runs;
		// dropping them by comm catches the late ones the time filter
		// misses without widening the window and hiding genuine early
		// workload caps. Counted toward InitWindowSuppressed alongside
		// the time-window drops -- both are "init suppressed before
		// reaching the cap set" from a reviewer's perspective.
		if isInitComm(ev.Proc.Comm) {
			st.suppressed++
			continue
		}
		if opts.InitWindowMs > 0 && ev.Timestamp-st.firstTsMs < int64(opts.InitWindowMs) {
			st.suppressed++
			continue
		}
		name := normalizeCap(ev.CapName)
		if name == "" {
			continue
		}
		// Offset origin is the earliest post-init-filter event across all
		// replicas. Under --all-matching, staggered replicas share one
		// timeline so offsets remain comparable across the profile.
		if !globalFirstSeen || ev.Timestamp < globalFirstTsMs {
			globalFirstTsMs = ev.Timestamp
			globalFirstSeen = true
		}
		comm := strings.TrimSpace(ev.Proc.Comm)
		rcs, ok := st.seen[name]
		if !ok {
			rcs = newCapStats()
			st.seen[name] = rcs
		}
		rcs.observe(ev.Timestamp, comm)
		ucs, ok := capUnion[name]
		if !ok {
			ucs = newCapStats()
			capUnion[name] = ucs
		}
		ucs.observe(ev.Timestamp, comm)
		if comm != "" {
			st.comms[comm] = struct{}{}
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}

	// Ambiguity: --image matched >1 replica without --all-matching.
	// PLAN.md §Target selection requires an error here so the tool never
	// silently emits the union of replica cap sets as a single profile.
	if opts.Image != "" && !opts.AllMatching && len(replicas) > 1 {
		labels := make([]string, 0, len(replicas))
		for rid, st := range replicas {
			if st.sampleName != "" {
				labels = append(labels, fmt.Sprintf("%s (%s)", st.sampleName, rid))
			} else {
				labels = append(labels, rid)
			}
		}
		sort.Strings(labels)
		return nil, &ambiguousSelectionError{image: opts.Image, replicas: labels}
	}

	s := NewSidecar()
	s.Target.Mode = opts.modeLabel()
	s.Target.Selector = opts.selector()
	s.Target.ReplicasObserved = len(replicas)

	commUnion := map[string]struct{}{}
	var totalSuppressed int
	for rid, st := range replicas {
		totalSuppressed += st.suppressed
		s.Target.PerReplicaEventCounts[rid] = st.eventCount
		s.Target.PerReplicaCaps[rid] = sortedKeys(st.seen)
		for c := range st.comms {
			commUnion[c] = struct{}{}
		}
	}
	s.Target.InitWindowSuppressed = totalSuppressed
	s.Target.DistinctComms = len(commUnion)

	// Image: explicit --image wins; otherwise copy any replica's observed
	// image. Under --container, the flag is an id/name/prefix, not an
	// image ref, so we do need the fallback to populate the sidecar.
	if opts.Image != "" {
		s.Image = opts.Image
	} else {
		for _, st := range replicas {
			if st.image != "" {
				s.Image = st.image
				break
			}
		}
	}

	allNames := sortedKeys(capUnion)
	for _, n := range allNames {
		cs := capUnion[n]
		cap := Capability{
			Name:        n,
			EventCount:  cs.eventCount,
			CommSamples: sortedKeys(cs.commSamples),
		}
		if cs.hasTs {
			cap.FirstSeenOffsetMs = cs.firstTsMs - globalFirstTsMs
			cap.LastSeenOffsetMs = cs.lastTsMs - globalFirstTsMs
		}
		s.Capabilities = append(s.Capabilities, cap)
	}

	// Cross-replica disagreement: any cap not present in every replica.
	// Undefined with <2 replicas -- PLAN.md specifies this list drives
	// the confidence rubric's replica-divergence factor (Step 6).
	if len(replicas) > 1 {
		dis := []string{}
		for _, n := range allNames {
			for _, st := range replicas {
				if _, ok := st.seen[n]; !ok {
					dis = append(dis, n)
					break
				}
			}
		}
		sort.Strings(dis)
		s.Target.ReplicaCapDisagreement = dis
	}

	// events_recorded is the count of cap events csd actually parsed
	// (post-matching, pre-init-filter). Drops are supplied by the
	// caller from ig's stderr (observe path) or from a fixture-stderr
	// file (tests); finaliseTraceHealth recomputes the rate after both
	// numerators are in hand.
	s.TraceHealth.EventsRecorded = recorded
	// Confidence scoring is a separate, callable-from-tests step. Callers
	// (run/observe) populate DurationSeconds and any other late-arriving
	// inputs before invoking computeConfidence so the rubric sees the
	// final sidecar.
	return s, nil
}

// sortedKeys returns the keys of m in sorted order. Used both for
// set-valued maps (struct{} / bool) and for per-cap stats maps; keys are
// the only thing we care about, value type is incidental.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// normalizeCap strips the CAP_ prefix so output is consistent regardless
// of whether IG emits "CAP_NET_RAW" or "NET_RAW" for a given release.
func normalizeCap(name string) string {
	name = strings.ToUpper(strings.TrimSpace(name))
	return strings.TrimPrefix(name, "CAP_")
}

// isInitComm reports whether comm names a container-init process whose
// capability checks belong to runc/init bring-up rather than the user's
// workload. v0.1-rc only filters runc:[*] (e.g. "runc:[2:INIT]"); other
// init shapes (containerd-shim, crio-init) are out of scope until they
// surface on a reference image.
func isInitComm(comm string) bool {
	return strings.HasPrefix(comm, "runc:")
}

// writeSidecar serializes s to path as indented JSON. Atomic semantics
// are not required for v0.1 -- consumers re-run the tool rather than
// read a sidecar mid-write, and the caller paths that produce s
// already ran to completion before we land here.
//
// Routes through writeJSON so the --out file and `--format json` stdout
// are byte-identical.
func writeSidecar(s *Sidecar, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeJSON(f, s)
}
