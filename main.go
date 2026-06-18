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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/ig"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
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
	// ObserveCapadd is the v0.5 dangerous-cap_add validator (CL-0011): the
	// inverse of caps. It reuses the trace_capabilities signal but aggregates
	// syscalls per dangerous cap and emits a validation (which caps are used,
	// by which syscalls, finer-grained alternatives, and removal candidates).
	ObserveCapadd = "capadd"
	// ObserveEgress is the v0.8 network-egress observer (ROADMAP §v0.8, issue
	// #136): it runs trace_tcp and derives the minimum outbound allowlist from
	// the destinations the workload actually contacted. A distinct output
	// family (firewall / NetworkPolicy rules), not the compose-security
	// formatters.
	ObserveEgress = "egress"
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

// optsMatch reports whether a capability event belongs to the selected
// target. It lives here rather than on attrib.Opts because attrib must stay
// event-type-agnostic (it would otherwise have to import the caps event type);
// the generic string-level decision is attrib.Opts.MatchesRuntime.
func optsMatch(o attrib.Opts, ev capEvent) bool {
	return o.MatchesRuntime(ev.Runtime.ContainerID, ev.Runtime.ContainerName, ev.Runtime.ContainerImage)
}

func main() {
	err := run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "csd:", err)
	}
	os.Exit(exit.CodeFor(err))
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
		observe          = fs.String("observe", ObserveCaps, "observer to run: caps (Linux capabilities), fs (read-only filesystem + tmpfs), devices (device decomposition), privileged (drop privileged: true → cap_add + devices), capadd (validate dangerous cap_add against observed syscalls), or egress (minimum outbound allowlist from observed connects)")
		capAddIn         = fs.String("cap-add", "", "capadd observer: comma-separated currently-granted caps to validate (e.g. SYS_ADMIN,NET_RAW); enables unused-cap detection and a recommended minimized cap_add. Default: report observed dangerous-cap usage")
		mountsFixture    = fs.String("mounts-fixture", "", "fs observer only: read container mount destinations from this `docker inspect` .Mounts JSON instead of running docker inspect")
		deviceFixture    = fs.String("device-fixture", "", "privileged observer only: read the trace_open NDJSON for the devices half from this file (the --fixture file supplies the trace_capabilities half)")
		fixture          = fs.String("fixture", "", "read ig-format NDJSON from this file instead of spawning ig")
		fixtureErr       = fs.String("fixture-stderr", "", "fixture-mode only: file of ig stderr lines; drops parsed as if piped from live ig")
		inspectFixture   = fs.String("inspect-fixture", "", "read pre-captured image-inspection JSON from this file instead of running `docker inspect`")
		duration         = fs.Duration("duration", 30*time.Second, "observation window (ignored in --fixture mode)")
		igBin            = fs.String("ig", "ig", "path to the ig binary")
		initWindowMs     = fs.Int("init-window-ms", 500, "drop capability events observed within this many ms of the first matching event (0 disables)")
		outPath          = fs.String("out", "", "write canonical JSON evidence sidecar to this file (stdout still prints the chosen --format)")
		format           = fs.String("format", FormatCompose, "output format for stdout (compose, compose-patch, compose-lint-profile, docker-run, json, k8s, oci; egress-only: nftables, k8s-networkpolicy)")
		allowExploratory = fs.Bool("allow-exploratory", false, "compose-lint-profile only: emit under exploratory: even when the acceptance contract is not met")
		workload         = fs.String("workload", "", "path to the user-supplied workload script that exercised the container; recorded on the sidecar and required by the compose-lint-profile gate")
		composeIn        = fs.String("compose-in", "", "compose-patch only: path to the user's compose file to diff against")
		composeService   = fs.String("service", "", "compose-patch only: name of the service under services: whose cap_drop/cap_add to rewrite")
	)
	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError surfaces -h/--help as ErrHelp and bad
		// flags as parse errors. CI integrators want both as EX_USAGE.
		return exit.WrapCoded(exit.Usage, err)
	}

	if *container != "" && *image != "" {
		return exit.CodedErrorf(exit.Usage, "--container and --image are mutually exclusive")
	}
	if *allMatching && *image == "" {
		return exit.CodedErrorf(exit.Usage, "--all-matching requires --image")
	}
	if *fixture == "" && *container == "" && *image == "" {
		return exit.CodedErrorf(exit.Usage, "one of --container or --image is required (or pass --fixture <file> to read pre-captured events)")
	}
	switch *format {
	case FormatCompose, FormatComposePatch, FormatComposeLintEntry, FormatDockerRun, FormatJSON, FormatK8s, FormatOCI, FormatNftables, FormatK8sNetworkPolicy:
		// implemented
	default:
		return exit.CodedErrorf(exit.Usage, "--format %q not recognized; supported: %s, %s, %s, %s, %s, %s, %s, %s, %s", *format, FormatCompose, FormatComposePatch, FormatComposeLintEntry, FormatDockerRun, FormatJSON, FormatK8s, FormatOCI, FormatNftables, FormatK8sNetworkPolicy)
	}
	// nftables / k8s-networkpolicy are the v0.8 egress output family and are not
	// meaningful for the compose-security observers; reject early rather than
	// silently no-op in their formatter switches.
	if (*format == FormatNftables || *format == FormatK8sNetworkPolicy) && *observe != ObserveEgress {
		return exit.CodedErrorf(exit.Usage, "--format %s is only valid with --observe %s", *format, ObserveEgress)
	}
	switch *observe {
	case ObserveCaps, ObserveFS, ObserveDevices, ObservePrivileged, ObserveCapadd, ObserveEgress:
		// recognized
	default:
		return exit.CodedErrorf(exit.Usage, "--observe %q not recognized; supported: %s, %s, %s, %s, %s, %s", *observe, ObserveCaps, ObserveFS, ObserveDevices, ObservePrivileged, ObserveCapadd, ObserveEgress)
	}
	if *observe != ObserveFS && *mountsFixture != "" {
		return exit.CodedErrorf(exit.Usage, "--mounts-fixture is only meaningful with --observe %s", ObserveFS)
	}
	if *observe != ObservePrivileged && *deviceFixture != "" {
		return exit.CodedErrorf(exit.Usage, "--device-fixture is only meaningful with --observe %s", ObservePrivileged)
	}
	if *observe != ObserveCapadd && *capAddIn != "" {
		return exit.CodedErrorf(exit.Usage, "--cap-add is only meaningful with --observe %s", ObserveCapadd)
	}
	// Workload is recorded on the sidecar and surfaced as a confidence factor
	// (both observers); the compose-lint contribution gate also requires the
	// file to be readable. Validate before either observe path so a typo'd
	// path fails fast (EX_USAGE) rather than after a full observation window.
	if *workload != "" {
		if _, err := os.Stat(*workload); err != nil {
			return exit.WrapCoded(exit.Usage, fmt.Errorf("--workload %q: %w", *workload, err))
		}
	}
	// The v0.8 egress observer (trace_tcp) derives an outbound allowlist into a
	// distinct output family (firewall / NetworkPolicy rules), not the
	// compose-security formatters — so it takes its own produce→format path and
	// returns before the capability formatter switch. This change wires the JSON
	// sidecar (+ --out, --workload, confidence, drop abort); the nftables +
	// k8s-networkpolicy emitters are the follow-on (#136).
	if *observe == ObserveEgress {
		// Egress supports json (the canonical sidecar) plus its two enforcement
		// formatters; the compose-security formats don't map onto an allowlist.
		switch *format {
		case FormatJSON, FormatNftables, FormatK8sNetworkPolicy:
			// implemented
		default:
			return exit.CodedErrorf(exit.Usage, "--observe %s supports --format %s, %s, or %s (not %s)", ObserveEgress, FormatJSON, FormatNftables, FormatK8sNetworkPolicy, *format)
		}
		s, err := produceEgressObservation(egressPipelineOpts{
			AggregateOpts: attrib.Opts{
				Container:    *container,
				Image:        *image,
				AllMatching:  *allMatching,
				InitWindowMs: *initWindowMs,
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
		case FormatJSON:
			if err := writeJSON(stdout, s); err != nil {
				return fmt.Errorf("write json: %w", err)
			}
		case FormatNftables:
			if err := writeEgressNftables(stdout, s); err != nil {
				return fmt.Errorf("write nftables: %w", err)
			}
		case FormatK8sNetworkPolicy:
			if err := writeEgressNetworkPolicy(stdout, s); err != nil {
				return fmt.Errorf("write k8s-networkpolicy: %w", err)
			}
		}
		if *outPath != "" {
			if err := writeSidecar(s, *outPath); err != nil {
				return fmt.Errorf("write sidecar: %w", err)
			}
		}
		if s.TraceHealth.DropRate >= exit.DropRateAbort {
			return exit.CodedErrorf(exit.DropRateExcessive,
				"trace_health drop rate %.4f >= %.2f; profile not trustworthy (events_recorded=%d events_dropped=%d)",
				s.TraceHealth.DropRate, exit.DropRateAbort,
				s.TraceHealth.EventsRecorded, s.TraceHealth.EventsDropped,
			)
		}
		return nil
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
				return exit.CodedErrorf(exit.Usage, "--format %s requires both --compose-in <path> and --service <name>", FormatComposePatch)
			}
			if _, statErr := os.Stat(*composeIn); statErr != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("--compose-in %q: %w", *composeIn, statErr))
			}
		} else if *composeIn != "" || *composeService != "" {
			return exit.CodedErrorf(exit.Usage, "--compose-in / --service are only meaningful with --format %s", FormatComposePatch)
		}
		if *allowExploratory && *format != FormatComposeLintEntry {
			return exit.CodedErrorf(exit.Usage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
		}
		s, err := produceFSObservation(fsPipelineOpts{
			AggregateOpts: attrib.Opts{
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
				return exit.WrapCoded(exit.Usage, fmt.Errorf("read --compose-in %q: %w", *composeIn, readErr))
			}
			if err := writeFSComposePatch(stdout, *s.FSRecommendation, raw, *composeIn, *composeService); err != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("write fs compose-patch: %w", err))
			}
		case FormatComposeLintEntry:
			if err := writeFSComposeLintProfile(stdout, s, *allowExploratory); err != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("write fs compose-lint-profile: %w", err))
			}
		}
		if *outPath != "" {
			if err := writeSidecar(s, *outPath); err != nil {
				return fmt.Errorf("write sidecar: %w", err)
			}
		}
		if s.TraceHealth.DropRate >= exit.DropRateAbort {
			return exit.CodedErrorf(exit.DropRateExcessive,
				"trace_health drop rate %.4f >= %.2f; profile not trustworthy (events_recorded=%d events_dropped=%d)",
				s.TraceHealth.DropRate, exit.DropRateAbort,
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
				return exit.CodedErrorf(exit.Usage, "--format %s requires both --compose-in <path> and --service <name>", FormatComposePatch)
			}
			if _, statErr := os.Stat(*composeIn); statErr != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("--compose-in %q: %w", *composeIn, statErr))
			}
		} else if *composeIn != "" || *composeService != "" {
			return exit.CodedErrorf(exit.Usage, "--compose-in / --service are only meaningful with --format %s", FormatComposePatch)
		}
		if *allowExploratory && *format != FormatComposeLintEntry {
			return exit.CodedErrorf(exit.Usage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
		}
		s, err := produceDeviceObservation(devicePipelineOpts{
			AggregateOpts: attrib.Opts{
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
				return exit.WrapCoded(exit.Usage, fmt.Errorf("read --compose-in %q: %w", *composeIn, readErr))
			}
			if err := writeDeviceComposePatch(stdout, *s.DeviceRecommendation, raw, *composeIn, *composeService); err != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("write device compose-patch: %w", err))
			}
		case FormatComposeLintEntry:
			if err := writeDeviceComposeLintProfile(stdout, s, *allowExploratory); err != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("write device compose-lint-profile: %w", err))
			}
		}
		if *outPath != "" {
			if err := writeSidecar(s, *outPath); err != nil {
				return fmt.Errorf("write sidecar: %w", err)
			}
		}
		if s.TraceHealth.DropRate >= exit.DropRateAbort {
			return exit.CodedErrorf(exit.DropRateExcessive,
				"trace_health drop rate %.4f >= %.2f; profile not trustworthy (events_recorded=%d events_dropped=%d)",
				s.TraceHealth.DropRate, exit.DropRateAbort,
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
				return exit.CodedErrorf(exit.Usage, "--format %s requires both --compose-in <path> and --service <name>", FormatComposePatch)
			}
			if _, statErr := os.Stat(*composeIn); statErr != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("--compose-in %q: %w", *composeIn, statErr))
			}
		} else if *composeIn != "" || *composeService != "" {
			return exit.CodedErrorf(exit.Usage, "--compose-in / --service are only meaningful with --format %s", FormatComposePatch)
		}
		if *allowExploratory && *format != FormatComposeLintEntry {
			return exit.CodedErrorf(exit.Usage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
		}
		s, err := producePrivilegedObservation(privilegedPipelineOpts{
			AggregateOpts: attrib.Opts{
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
				return exit.WrapCoded(exit.Usage, fmt.Errorf("read --compose-in %q: %w", *composeIn, readErr))
			}
			if err := writePrivilegedComposePatch(stdout, s, raw, *composeIn, *composeService); err != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("write privileged compose-patch: %w", err))
			}
		case FormatComposeLintEntry:
			if err := writePrivilegedComposeLintProfile(stdout, s, *allowExploratory); err != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("write privileged compose-lint-profile: %w", err))
			}
		}
		if *outPath != "" {
			if err := writeSidecar(s, *outPath); err != nil {
				return fmt.Errorf("write sidecar: %w", err)
			}
		}
		emitAdvisoryWarnings(s, stderr)
		if s.TraceHealth.DropRate >= exit.DropRateAbort {
			return exit.CodedErrorf(exit.DropRateExcessive,
				"trace_health drop rate %.4f >= %.2f; profile not trustworthy (events_recorded=%d events_dropped=%d)",
				s.TraceHealth.DropRate, exit.DropRateAbort,
				s.TraceHealth.EventsRecorded, s.TraceHealth.EventsDropped,
			)
		}
		return nil
	}
	// The v0.5 dangerous-cap_add validator (CL-0011) reuses the trace_capabilities
	// signal but aggregates syscalls per dangerous cap, emitting a validation in
	// the Sidecar's capadd_validation block. It takes its own produce→format path
	// and returns before the capability formatter switch. All seven formatters are
	// implemented; the advisory is always emitted, and the concrete recommended
	// cap_add only when --cap-add supplies the granted set.
	if *observe == ObserveCapadd {
		if *format == FormatComposePatch {
			if *composeIn == "" || *composeService == "" {
				return exit.CodedErrorf(exit.Usage, "--format %s requires both --compose-in <path> and --service <name>", FormatComposePatch)
			}
			if _, statErr := os.Stat(*composeIn); statErr != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("--compose-in %q: %w", *composeIn, statErr))
			}
		} else if *composeIn != "" || *composeService != "" {
			return exit.CodedErrorf(exit.Usage, "--compose-in / --service are only meaningful with --format %s", FormatComposePatch)
		}
		if *allowExploratory && *format != FormatComposeLintEntry {
			return exit.CodedErrorf(exit.Usage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
		}
		// The granted set (--cap-add) is the validate-set when supplied — and the
		// switch that enables unused-cap detection + a recommended minimized
		// cap_add. Without it the validator scrutinizes the dangerousCaps default
		// and reports only observed usage.
		granted := parseCapSet(*capAddIn)
		activeSet := granted
		hasGranted := granted != nil
		if activeSet == nil {
			activeSet = dangerousCaps
		}
		s, err := produceCapaddObservation(capaddPipelineOpts{
			AggregateOpts: attrib.Opts{
				Container:   *container,
				Image:       *image,
				AllMatching: *allMatching,
			},
			ActiveSet: activeSet,
			Granted:   hasGranted,
			Fixture:   *fixture,
			IGBin:     *igBin,
			Duration:  *duration,
			Workload:  *workload,
		}, stderr)
		if err != nil {
			return err
		}
		switch *format {
		case FormatCompose:
			if err := writeCapaddCompose(stdout, s.CapaddValidation); err != nil {
				return fmt.Errorf("write capadd compose: %w", err)
			}
		case FormatJSON:
			if err := writeJSON(stdout, s); err != nil {
				return fmt.Errorf("write json: %w", err)
			}
		case FormatDockerRun:
			if err := writeCapaddDockerRun(stdout, s.CapaddValidation); err != nil {
				return fmt.Errorf("write capadd docker-run: %w", err)
			}
		case FormatK8s:
			if err := writeCapaddK8s(stdout, s.CapaddValidation); err != nil {
				return fmt.Errorf("write capadd k8s: %w", err)
			}
		case FormatOCI:
			if err := writeCapaddOCI(stdout, s.CapaddValidation); err != nil {
				return fmt.Errorf("write capadd oci: %w", err)
			}
		case FormatComposePatch:
			raw, readErr := os.ReadFile(*composeIn)
			if readErr != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("read --compose-in %q: %w", *composeIn, readErr))
			}
			if err := writeCapaddComposePatch(stdout, s.CapaddValidation, raw, *composeIn, *composeService); err != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("write capadd compose-patch: %w", err))
			}
		case FormatComposeLintEntry:
			if err := writeCapaddComposeLintProfile(stdout, s, *allowExploratory); err != nil {
				return exit.WrapCoded(exit.Usage, fmt.Errorf("write capadd compose-lint-profile: %w", err))
			}
		}
		if *outPath != "" {
			if err := writeSidecar(s, *outPath); err != nil {
				return fmt.Errorf("write sidecar: %w", err)
			}
		}
		emitAdvisoryWarnings(s, stderr)
		if s.TraceHealth.DropRate >= exit.DropRateAbort {
			return exit.CodedErrorf(exit.DropRateExcessive,
				"trace_health drop rate %.4f >= %.2f; profile not trustworthy (events_recorded=%d events_dropped=%d)",
				s.TraceHealth.DropRate, exit.DropRateAbort,
				s.TraceHealth.EventsRecorded, s.TraceHealth.EventsDropped,
			)
		}
		return nil
	}
	if *allowExploratory && *format != FormatComposeLintEntry {
		return exit.CodedErrorf(exit.Usage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
	}
	// compose-patch needs both --compose-in and --service; reject the
	// flags elsewhere so a future user doesn't believe they have an
	// effect with another formatter.
	if *format == FormatComposePatch {
		if *composeIn == "" || *composeService == "" {
			return exit.CodedErrorf(exit.Usage, "--format %s requires both --compose-in <path> and --service <name>", FormatComposePatch)
		}
		if _, err := os.Stat(*composeIn); err != nil {
			return exit.WrapCoded(exit.Usage, fmt.Errorf("--compose-in %q: %w", *composeIn, err))
		}
	} else if *composeIn != "" || *composeService != "" {
		return exit.CodedErrorf(exit.Usage, "--compose-in / --service are only meaningful with --format %s", FormatComposePatch)
	}

	s, err := produceObservation(observePipelineOpts{
		AggregateOpts: attrib.Opts{
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
			return exit.WrapCoded(exit.Usage, fmt.Errorf("read --compose-in %q: %w", *composeIn, readErr))
		}
		if err := writeComposePatch(stdout, s, raw, *composeIn, *composeService); err != nil {
			// Service-not-found / services-block-missing are usage
			// errors: the user pointed at a file that can't host the
			// patch, not a runtime failure of csd.
			return exit.WrapCoded(exit.Usage, fmt.Errorf("write compose-patch: %w", err))
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
			return exit.WrapCoded(exit.Usage, fmt.Errorf("write compose-lint-profile: %w", err))
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
	if s.TraceHealth.DropRate >= exit.DropRateAbort {
		return exit.CodedErrorf(exit.DropRateExcessive,
			"trace_health drop rate %.4f >= %.2f; profile not trustworthy (events_recorded=%d events_dropped=%d)",
			s.TraceHealth.DropRate, exit.DropRateAbort,
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
func emitAdvisoryWarnings(s *sidecar.Sidecar, stderr io.Writer) {
	if stderr == nil {
		return
	}
	if s.TraceHealth.DropRate > 0 && s.TraceHealth.DropRate < exit.DropRateAbort {
		fmt.Fprintf(stderr,
			"csd: warning: trace_health drop_rate %.4f (%d dropped / %d recorded); below %.2f abort threshold but profile may be incomplete\n",
			s.TraceHealth.DropRate, s.TraceHealth.EventsDropped, s.TraceHealth.EventsRecorded, exit.DropRateAbort,
		)
	}
	if len(s.Target.ReplicaCapDisagreement) > 0 {
		fmt.Fprintf(stderr,
			"csd: warning: replicas disagree on %d cap(s) [%s]; --all-matching produced a union profile that no single replica required\n",
			len(s.Target.ReplicaCapDisagreement),
			strings.Join(s.Target.ReplicaCapDisagreement, ", "),
		)
	}
	// The privileged decomposition is partial at v0.3 (caps + devices only,
	// not AppArmor/seccomp). Warn on every format — including compose-patch
	// and json, whose output bodies don't carry the `#` caveat comment — so a
	// user never acts on "drop privileged: true" without seeing the gap.
	if s.PrivilegedDecomposition != nil && s.PrivilegedDecomposition.Partial {
		fmt.Fprintf(stderr, "csd: warning: %s\n", s.PrivilegedDecomposition.SecurityOpt)
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
	AggregateOpts  attrib.Opts
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
// translated here: ambiguous-selection becomes exit.TargetAmbiguous,
// ig-missing flows through observe()'s wrapped error verbatim. Drop-
// rate abort is NOT applied here -- callers may want to emit the
// formatted artifact (run) or the verify result (runVerify) before
// surfacing the abort, and centralising that here would force a flag
// on this helper that neither caller needs.
func produceObservation(opts observePipelineOpts, stderr io.Writer) (*sidecar.Sidecar, error) {
	observedAt := time.Now().UTC()

	var (
		s   *sidecar.Sidecar
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
			s.TraceHealth.EventsDropped = ig.ParseIGStderr(errSrc, nil)
			errSrc.Close()
		}
	} else {
		noteWSL2IfDetected(stderr)
		if verr := ig.CheckIGVersion(opts.IGBin, stderr); verr != nil {
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
		var amb *exit.AmbiguousSelectionError
		if errors.As(err, &amb) {
			return nil, exit.WrapCoded(exit.TargetAmbiguous, err)
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
func observe(ctx context.Context, igBin string, opts attrib.Opts, stderrSink io.Writer) (*sidecar.Sidecar, error) {
	cmd := exec.CommandContext(ctx, igBin, "run", ig.TraceCapabilitiesGadget, "--output", "json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		if exit.IsIGMissing(err) {
			return nil, exit.WrapCoded(exit.IGMissing, fmt.Errorf("ig binary %q not available: %w", igBin, err))
		}
		return nil, fmt.Errorf("start %s: %w", igBin, err)
	}

	var (
		wg   sync.WaitGroup
		lost int
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		lost = ig.ParseIGStderr(stderrPipe, stderrSink)
	}()

	s, aggErr := aggregate(stdout, opts)
	earlyErr := aggErr != nil && !errors.Is(aggErr, io.EOF)
	if earlyErr {
		// Aggregation bailed early (oversized untrusted stdout line, or a
		// target-selection ambiguity) with ig's stdout pipe undrained; ig will
		// block on the full pipe and never exit, so kill it now rather than let
		// the stderr drain and cmd.Wait() below stall for the rest of the
		// --duration window (a fast exit.TargetAmbiguous is the intended path).
		_ = cmd.Process.Kill()
	}
	// Join the stderr-drain goroutine BEFORE cmd.Wait(): Wait closes the pipe,
	// and the documented StderrPipe contract requires the read to finish first,
	// else an in-flight Read can drop a trailing `lost N` line. With the join
	// here, the lost-counter read below needs no extra synchronisation.
	wg.Wait()
	waitErr := cmd.Wait()
	if s != nil {
		s.TraceHealth.EventsDropped = lost
	}
	if earlyErr {
		return nil, aggErr
	}
	if waitErr != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("ig exited: %w", waitErr)
	}
	return s, nil
}

// finaliseTraceHealth computes DropRate once both sides of the ratio
// are known. recorded is the count of events csd parsed; dropped is
// ig's stderr-reported loss. Ratio is dropped / recorded to preserve
// the pre-Step-11 rubric thresholds; recomputing against the total
// population (dropped + recorded) would shift every threshold and is
// out of scope for the parser realignment.
func finaliseTraceHealth(th *sidecar.TraceHealth) {
	if th.EventsRecorded > 0 {
		th.DropRate = float64(th.EventsDropped) / float64(th.EventsRecorded)
	} else if th.EventsDropped > 0 {
		// All-dropped-no-recorded is a pathological case we can still
		// report as "everything lost". Without this branch a 0-record
		// run with losses would look clean.
		th.DropRate = 1.0
	}
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
func aggregate(r io.Reader, opts attrib.Opts) (*sidecar.Sidecar, error) {
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
			// Hard-fail on a malformed line, matching the fs/device/capadd
			// aggregators (deep-review L3). Silently skipping would yield a
			// SMALLER derived cap set with no signal — the dangerous direction,
			// since a user could then drop a cap the workload needs. The pinned
			// ig version (enforced by checkIGVersion) emits one clean JSON event
			// per stdout line, so a parse failure means corrupt input, not a
			// benign diagnostic line.
			return nil, fmt.Errorf("parse trace_capabilities event: %w", err)
		}
		if !optsMatch(opts, ev) {
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

	// Ambiguity: the selector (--image, or a too-short --container prefix)
	// matched >1 replica without --all-matching. PLAN.md §Target selection
	// requires an error here so the tool never silently emits the union of
	// replica cap sets as a single profile.
	if opts.Ambiguous(len(replicas)) {
		labels := make([]string, 0, len(replicas))
		for rid, st := range replicas {
			if st.sampleName != "" {
				labels = append(labels, fmt.Sprintf("%s (%s)", st.sampleName, rid))
			} else {
				labels = append(labels, rid)
			}
		}
		sort.Strings(labels)
		return nil, opts.NewAmbiguousSelectionError(labels)
	}

	s := sidecar.NewSidecar()
	s.Target.Mode = opts.ModeLabel()
	s.Target.Selector = opts.Selector()
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
		cap := sidecar.Capability{
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
func writeSidecar(s *sidecar.Sidecar, path string) error {
	// 0600, not os.Create's 0666: the sidecar is security evidence written by a
	// root-equivalent process; it should not be world- or group-readable
	// (deep-review L4).
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeJSON(f, s)
}
