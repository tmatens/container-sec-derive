// Package cli is csd's command layer: flag parsing, the --observe / --format
// dispatch, and the per-observer wiring that turns a parsed invocation into an
// observation and renders it. Run is the single entry point; cmd/csd is a thin
// shim over it (and a future cmd/csdd daemon would reuse the same internal/*
// packages without going through here). CLI assumptions live here — flag
// parsing and stdout writing belong in this package, not in internal/observe /
// internal/format / internal/sidecar (os.Exit stays in cmd).
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/deploycheck"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/format"
	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/observe/capadd"
	"github.com/tmatens/container-sec-derive/internal/observe/caps"
	"github.com/tmatens/container-sec-derive/internal/observe/devices"
	"github.com/tmatens/container-sec-derive/internal/observe/egress"
	"github.com/tmatens/container-sec-derive/internal/observe/fs"
	"github.com/tmatens/container-sec-derive/internal/observe/privileged"
	"github.com/tmatens/container-sec-derive/internal/runtime"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
	"github.com/tmatens/container-sec-derive/internal/verify"
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

// Format identifiers — the --format flag value contract. Centralized so the
// "supported formats" list has one source of truth; the renderers live in
// internal/format.
const (
	FormatCompose          = "compose"
	FormatComposePatch     = "compose-patch"
	FormatDockerRun        = "docker-run"
	FormatOCI              = "oci"
	FormatK8s              = "k8s"
	FormatJSON             = "json"
	FormatComposeLintEntry = "compose-lint-profile"
	FormatNftables         = "nftables"
	FormatK8sNetworkPolicy = "k8s-networkpolicy"
)

// validateComposeFormatOpts enforces the --compose-in/--service contract shared
// by every observer's compose-patch branch: when --format compose-patch is
// selected both flags are required and --compose-in must exist; otherwise
// neither flag is meaningful and supplying one is a usage error. Centralized so
// the five per-observer copies (caps/fs/devices/privileged/capadd) cannot drift.
func validateComposeFormatOpts(formatMode string, composeIn, composeService *string) error {
	if formatMode == FormatComposePatch {
		if *composeIn == "" || *composeService == "" {
			return exit.CodedErrorf(exit.Usage, "--format %s requires both --compose-in <path> and --service <name>", FormatComposePatch)
		}
		if _, statErr := os.Stat(*composeIn); statErr != nil {
			return exit.WrapCoded(exit.Usage, fmt.Errorf("--compose-in %q: %w", *composeIn, statErr))
		}
	} else if *composeIn != "" || *composeService != "" {
		return exit.CodedErrorf(exit.Usage, "--compose-in / --service are only meaningful with --format %s", FormatComposePatch)
	}
	return nil
}

// renderObserverFormat runs the shared six-format compose-security dispatch (plus
// json) for one observer's Formatter, so the five observer paths (caps/fs/devices/
// privileged/capadd) no longer each carry a near-identical switch that could
// drift. obsLabel qualifies the error message the way the old per-observer copies
// did -- "" for caps ("write compose"), "fs"/"device"/"privileged"/"capadd" for
// the others ("write fs compose") -- keeping surfaced errors byte-identical.
// compose-patch reads --compose-in here (usage error on read failure) and, like
// compose-lint-profile, wraps its write error as EX_USAGE; the caller has already
// validated the flag combination via validateComposeFormatOpts. Both are
// usage-class: a compose-patch failure means the user pointed at a file that
// can't host the patch (service-not-found / services-block-missing), and a
// compose-lint-profile failure means the artifact didn't clear the contribution
// contract -- surfacing EX_USAGE lets CI catch it rather than accept empty stdout.
func renderObserverFormat(stdout io.Writer, formatMode string, f format.Formatter, s *sidecar.Sidecar, obsLabel, composeIn, composeService string, allowExploratory bool) error {
	label := obsLabel
	if label != "" {
		label += " "
	}
	switch formatMode {
	case FormatCompose:
		if err := f.Compose(stdout, s); err != nil {
			return fmt.Errorf("write %scompose: %w", label, err)
		}
	case FormatJSON:
		if err := format.WriteJSON(stdout, s); err != nil {
			return fmt.Errorf("write json: %w", err)
		}
	case FormatDockerRun:
		if err := f.DockerRun(stdout, s); err != nil {
			return fmt.Errorf("write %sdocker-run: %w", label, err)
		}
	case FormatK8s:
		if err := f.K8s(stdout, s); err != nil {
			return fmt.Errorf("write %sk8s: %w", label, err)
		}
	case FormatOCI:
		if err := f.OCI(stdout, s); err != nil {
			return fmt.Errorf("write %soci: %w", label, err)
		}
	case FormatComposePatch:
		raw, readErr := os.ReadFile(composeIn)
		if readErr != nil {
			return exit.WrapCoded(exit.Usage, fmt.Errorf("read --compose-in %q: %w", composeIn, readErr))
		}
		if err := f.ComposePatch(stdout, s, raw, composeIn, composeService); err != nil {
			return exit.WrapCoded(exit.Usage, fmt.Errorf("write %scompose-patch: %w", label, err))
		}
	case FormatComposeLintEntry:
		if err := f.ComposeLintProfile(stdout, s, allowExploratory); err != nil {
			return exit.WrapCoded(exit.Usage, fmt.Errorf("write %scompose-lint-profile: %w", label, err))
		}
	}
	return nil
}

func Run(args []string, stdout, stderr io.Writer) error {
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
		return verify.RunVerify(args[1:], stdout, stderr)
	}
	// deploy-check re-derives a service's minimum from its committed compose and
	// diffs it against the declared cap_add (issue #355). Like verify it owns its
	// own flagset and returns coded errors, so it dispatches before the observe
	// flag parser.
	if len(args) > 0 && args[0] == "deploy-check" {
		return deploycheck.RunDeployCheck(args[1:], stdout, stderr)
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

	flags := flag.NewFlagSet("csd", flag.ContinueOnError)
	// Discard the flag package's own output. On a parse error it prints the bare
	// message and a full usage dump; main() then repeats the message with the
	// "csd: " prefix, so the error appeared twice (#291). Suppressing it here
	// leaves the single prefixed "csd: <err>" line. -h/--help is reprinted
	// explicitly below (it is not an error, so it must not be swallowed).
	flags.SetOutput(io.Discard)
	var (
		container        = flags.String("container", "", "target container id or name (mutually exclusive with --image)")
		image            = flags.String("image", "", "select containers by image reference (errors if >1 match without --all-matching)")
		allMatching      = flags.Bool("all-matching", false, "aggregate across all replicas matching --image")
		observeMode      = flags.String("observe", ObserveCaps, "observer to run: caps (Linux capabilities), fs (read-only filesystem + tmpfs), devices (device decomposition), privileged (drop privileged: true → cap_add + devices), capadd (validate dangerous cap_add against observed syscalls), or egress (minimum outbound allowlist from observed connects)")
		capAddIn         = flags.String("cap-add", "", "capadd observer: comma-separated currently-granted caps to validate (e.g. SYS_ADMIN,NET_RAW); enables unused-cap detection and a recommended minimized cap_add. Default: report observed dangerous-cap usage")
		mountsFixture    = flags.String("mounts-fixture", "", "fs observer only: read container mount destinations from this `docker inspect` .Mounts JSON instead of running docker inspect")
		deviceFixture    = flags.String("device-fixture", "", "privileged observer only: read the trace_open NDJSON for the devices half from this file (the --fixture file supplies the trace_capabilities half)")
		dnsFixture       = flags.String("dns-fixture", "", "egress observer only: read trace_dns NDJSON from this file to correlate IP->hostname and the DNS resolver into the allowlist (the --fixture file supplies the trace_tcp half)")
		fixture          = flags.String("fixture", "", "read ig-format NDJSON from this file instead of spawning ig")
		fixtureErr       = flags.String("fixture-stderr", "", "fixture-mode only: file of ig stderr lines; drops parsed as if piped from live ig")
		inspectFixture   = flags.String("inspect-fixture", "", "read pre-captured image-inspection JSON from this file instead of running `docker inspect`")
		duration         = flags.Duration("duration", 30*time.Second, "observation window (ignored in --fixture mode)")
		igBin            = flags.String("ig", "ig", "path to the ig binary")
		runtimeFlag      = flags.String("runtime", runtime.Default, "container CLI for image/mount inspection: docker or podman (does NOT affect ig, which auto-detects). Docker is the only per-PR-tested runtime")
		initWindowMs     = flags.Int("init-window-ms", 500, "drop capability events observed within this many ms of the first matching event (0 disables)")
		outPath          = flags.String("out", "", "write canonical JSON evidence sidecar to this file (stdout still prints the chosen --format)")
		formatMode       = flags.String("format", FormatCompose, "output format for stdout (compose, compose-patch, compose-lint-profile, docker-run, json, k8s, oci; egress-only: nftables, k8s-networkpolicy)")
		allowExploratory = flags.Bool("allow-exploratory", false, "compose-lint-profile only: emit under exploratory: even when the acceptance contract is not met")
		workload         = flags.String("workload", "", "path to the user-supplied workload script that exercised the container; recorded on the sidecar and required by the compose-lint-profile gate")
		gadgetFilter     = flags.Bool("gadget-filter", false, "--container targets only: push a --containername filter into the gadget so other workloads' events never enter the perf buffer (dramatically lowers the drop rate on busy hosts). Off by default: on some runtime/ig combinations (e.g. Docker 29's containerd image store) the in-gadget filter matches nothing and the run observes ZERO events — enable only on hosts where a filtered run has been verified to record events")
		composeIn        = flags.String("compose-in", "", "compose-patch only: path to the user's compose file to diff against")
		composeService   = flags.String("service", "", "compose-patch only: name of the service under services: whose cap_drop/cap_add to rewrite")
	)
	if err := flags.Parse(args); err != nil {
		// flag.ContinueOnError surfaces -h/--help as ErrHelp and bad flags as
		// parse errors. -h/--help is an explicit request, not a usage error:
		// print usage to stdout (the discarded writer swallowed the default) and
		// exit cleanly. A real bad flag stays EX_USAGE and main prints the single
		// "csd: <err>" line.
		if err == flag.ErrHelp {
			flags.SetOutput(stdout)
			flags.Usage()
			return nil
		}
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
	switch *formatMode {
	case FormatCompose, FormatComposePatch, FormatComposeLintEntry, FormatDockerRun, FormatJSON, FormatK8s, FormatOCI, FormatNftables, FormatK8sNetworkPolicy:
		// implemented
	default:
		return exit.CodedErrorf(exit.Usage, "--format %q not recognized; supported: %s, %s, %s, %s, %s, %s, %s, %s, %s", *formatMode, FormatCompose, FormatComposePatch, FormatComposeLintEntry, FormatDockerRun, FormatJSON, FormatK8s, FormatOCI, FormatNftables, FormatK8sNetworkPolicy)
	}
	// nftables / k8s-networkpolicy are the v0.8 egress output family and are not
	// meaningful for the compose-security observers; reject early rather than
	// silently no-op in their formatter switches.
	if (*formatMode == FormatNftables || *formatMode == FormatK8sNetworkPolicy) && *observeMode != ObserveEgress {
		return exit.CodedErrorf(exit.Usage, "--format %s is only valid with --observe %s", *formatMode, ObserveEgress)
	}
	switch *observeMode {
	case ObserveCaps, ObserveFS, ObserveDevices, ObservePrivileged, ObserveCapadd, ObserveEgress:
		// recognized
	default:
		return exit.CodedErrorf(exit.Usage, "--observe %q not recognized; supported: %s, %s, %s, %s, %s, %s", *observeMode, ObserveCaps, ObserveFS, ObserveDevices, ObservePrivileged, ObserveCapadd, ObserveEgress)
	}
	if *observeMode != ObserveFS && *mountsFixture != "" {
		return exit.CodedErrorf(exit.Usage, "--mounts-fixture is only meaningful with --observe %s", ObserveFS)
	}
	if *observeMode != ObservePrivileged && *deviceFixture != "" {
		return exit.CodedErrorf(exit.Usage, "--device-fixture is only meaningful with --observe %s", ObservePrivileged)
	}
	if *observeMode != ObserveEgress && *dnsFixture != "" {
		return exit.CodedErrorf(exit.Usage, "--dns-fixture is only meaningful with --observe %s", ObserveEgress)
	}
	if *observeMode != ObserveCapadd && *capAddIn != "" {
		return exit.CodedErrorf(exit.Usage, "--cap-add is only meaningful with --observe %s", ObserveCapadd)
	}
	// Resolve the container CLI for inspect/history/mounts (docker/podman). An
	// unknown value fails fast with EX_USAGE rather than shelling out to a
	// missing binary mid-run. Only caps/fs/privileged shell out; the others
	// ignore it.
	runtimeBin, rtErr := runtime.Resolve(*runtimeFlag)
	if rtErr != nil {
		return exit.WrapCoded(exit.Usage, rtErr)
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
	if *observeMode == ObserveEgress {
		// Egress supports json (the canonical sidecar) plus its two enforcement
		// formatters; the compose-security formats don't map onto an allowlist.
		switch *formatMode {
		case FormatJSON, FormatNftables, FormatK8sNetworkPolicy:
			// implemented
		default:
			return exit.CodedErrorf(exit.Usage, "--observe %s supports --format %s, %s, or %s (not %s)", ObserveEgress, FormatJSON, FormatNftables, FormatK8sNetworkPolicy, *formatMode)
		}
		s, err := egress.ProduceEgressObservation(egress.EgressPipelineOpts{
			AggregateOpts: attrib.Opts{
				Container:    *container,
				Image:        *image,
				AllMatching:  *allMatching,
				InitWindowMs: *initWindowMs,
			},
			Fixture:    *fixture,
			DNSFixture: *dnsFixture,
			IGBin:      *igBin,
			Duration:   *duration,
			Workload:   *workload,
		}, stderr)
		if err != nil {
			return err
		}
		switch *formatMode {
		case FormatJSON:
			if err := format.WriteJSON(stdout, s); err != nil {
				return fmt.Errorf("write json: %w", err)
			}
		case FormatNftables:
			if err := egress.WriteEgressNftables(stdout, s); err != nil {
				return fmt.Errorf("write nftables: %w", err)
			}
		case FormatK8sNetworkPolicy:
			if err := egress.WriteEgressNetworkPolicy(stdout, s); err != nil {
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
	if *observeMode == ObserveFS {
		// All seven formatters are implemented for flags. compose-patch needs
		// --compose-in/--service (validated below, shared with the cap path);
		// compose-lint-profile honors --allow-exploratory.
		if err := validateComposeFormatOpts(*formatMode, composeIn, composeService); err != nil {
			return err
		}
		if *allowExploratory && *formatMode != FormatComposeLintEntry {
			return exit.CodedErrorf(exit.Usage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
		}
		s, err := fs.ProduceFSObservation(fs.FSPipelineOpts{
			AggregateOpts: attrib.Opts{
				Container:   *container,
				Image:       *image,
				AllMatching: *allMatching,
			},
			Fixture:       *fixture,
			MountsFixture: *mountsFixture,
			RuntimeBin:    runtimeBin,
			IGBin:         *igBin,
			Duration:      *duration,
			Workload:      *workload,
			GadgetFilter:  *gadgetFilter,
		}, stderr)
		if err != nil {
			return err
		}
		if err := renderObserverFormat(stdout, *formatMode, format.FSFormatter, s, "fs", *composeIn, *composeService, *allowExploratory); err != nil {
			return err
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
	if *observeMode == ObserveDevices {
		// All seven formatters are now implemented for devices. compose-patch
		// needs --compose-in/--service (validated below, shared shape with the
		// cap/fs paths); compose-lint-profile honors --allow-exploratory.
		if err := validateComposeFormatOpts(*formatMode, composeIn, composeService); err != nil {
			return err
		}
		if *allowExploratory && *formatMode != FormatComposeLintEntry {
			return exit.CodedErrorf(exit.Usage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
		}
		s, err := devices.ProduceDeviceObservation(devices.DevicePipelineOpts{
			AggregateOpts: attrib.Opts{
				Container:   *container,
				Image:       *image,
				AllMatching: *allMatching,
			},
			Fixture:      *fixture,
			IGBin:        *igBin,
			Duration:     *duration,
			Workload:     *workload,
			GadgetFilter: *gadgetFilter,
			RuntimeBin:   runtimeBin,
		}, stderr)
		if err != nil {
			return err
		}
		if err := renderObserverFormat(stdout, *formatMode, format.DeviceFormatter, s, "device", *composeIn, *composeService, *allowExploratory); err != nil {
			return err
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
	if *observeMode == ObservePrivileged {
		// All seven formatters are implemented for privileged. compose-patch
		// needs --compose-in/--service; compose-lint-profile honors
		// --allow-exploratory (shared shape with the cap/fs/device paths).
		if err := validateComposeFormatOpts(*formatMode, composeIn, composeService); err != nil {
			return err
		}
		if *allowExploratory && *formatMode != FormatComposeLintEntry {
			return exit.CodedErrorf(exit.Usage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
		}
		s, err := privileged.ProducePrivilegedObservation(privileged.PrivilegedPipelineOpts{
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
			RuntimeBin:     runtimeBin,
			IGBin:          *igBin,
			Duration:       *duration,
			Workload:       *workload,
			GadgetFilter:   *gadgetFilter,
		}, stderr)
		if err != nil {
			return err
		}
		if err := renderObserverFormat(stdout, *formatMode, format.PrivilegedFormatter, s, "privileged", *composeIn, *composeService, *allowExploratory); err != nil {
			return err
		}
		if *outPath != "" {
			if err := writeSidecar(s, *outPath); err != nil {
				return fmt.Errorf("write sidecar: %w", err)
			}
		}
		observe.EmitAdvisoryWarnings(s, stderr, *fixture == "", *container, *image)
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
	if *observeMode == ObserveCapadd {
		if err := validateComposeFormatOpts(*formatMode, composeIn, composeService); err != nil {
			return err
		}
		if *allowExploratory && *formatMode != FormatComposeLintEntry {
			return exit.CodedErrorf(exit.Usage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
		}
		// The granted set (--cap-add) is the validate-set when supplied — and the
		// switch that enables unused-cap detection + a recommended minimized
		// cap_add. Without it the validator scrutinizes the dangerousCaps default
		// and reports only observed usage.
		granted := capadd.ParseCapSet(*capAddIn)
		activeSet := granted
		hasGranted := granted != nil
		if activeSet == nil {
			activeSet = capadd.DangerousCaps
		}
		s, err := capadd.ProduceCapaddObservation(capadd.CapaddPipelineOpts{
			AggregateOpts: attrib.Opts{
				Container:   *container,
				Image:       *image,
				AllMatching: *allMatching,
			},
			ActiveSet:    activeSet,
			Granted:      hasGranted,
			Fixture:      *fixture,
			IGBin:        *igBin,
			Duration:     *duration,
			Workload:     *workload,
			GadgetFilter: *gadgetFilter,
			RuntimeBin:   runtimeBin,
		}, stderr)
		if err != nil {
			return err
		}
		if err := renderObserverFormat(stdout, *formatMode, format.CapaddFormatter, s, "capadd", *composeIn, *composeService, *allowExploratory); err != nil {
			return err
		}
		if *outPath != "" {
			if err := writeSidecar(s, *outPath); err != nil {
				return fmt.Errorf("write sidecar: %w", err)
			}
		}
		observe.EmitAdvisoryWarnings(s, stderr, *fixture == "", *container, *image)
		if s.TraceHealth.DropRate >= exit.DropRateAbort {
			return exit.CodedErrorf(exit.DropRateExcessive,
				"trace_health drop rate %.4f >= %.2f; profile not trustworthy (events_recorded=%d events_dropped=%d)",
				s.TraceHealth.DropRate, exit.DropRateAbort,
				s.TraceHealth.EventsRecorded, s.TraceHealth.EventsDropped,
			)
		}
		return nil
	}
	if *allowExploratory && *formatMode != FormatComposeLintEntry {
		return exit.CodedErrorf(exit.Usage, "--allow-exploratory is only meaningful with --format %s", FormatComposeLintEntry)
	}
	// compose-patch needs both --compose-in and --service; reject the
	// flags elsewhere so a future user doesn't believe they have an
	// effect with another formatter.
	if err := validateComposeFormatOpts(*formatMode, composeIn, composeService); err != nil {
		return err
	}

	s, err := caps.ProduceObservation(caps.PipelineOpts{
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
		GadgetFilter:   *gadgetFilter,
	}, stderr)
	if err != nil {
		return err
	}
	if err := renderObserverFormat(stdout, *formatMode, format.CapsFormatter, s, "", *composeIn, *composeService, *allowExploratory); err != nil {
		return err
	}

	// Sidecar is written before the drop-rate abort so CI integrators
	// still get the artifact-with-caveat that PLAN.md §Exit codes
	// promises for code 21.
	if *outPath != "" {
		if err := writeSidecar(s, *outPath); err != nil {
			return fmt.Errorf("write sidecar: %w", err)
		}
	}

	observe.EmitAdvisoryWarnings(s, stderr, *fixture == "", *container, *image)

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

// writeSidecar serializes s to path as indented JSON. Atomic semantics
// are not required for v0.1 -- consumers re-run the tool rather than
// read a sidecar mid-write, and the caller paths that produce s
// already ran to completion before we land here.
//
// Routes through format.WriteJSON so the --out file and `--format json` stdout
// are byte-identical.
func writeSidecar(s *sidecar.Sidecar, path string) error {
	// 0600, not os.Create's 0666: the sidecar is security evidence written by a
	// root-equivalent process; it should not be world- or group-readable
	// (deep-review L4).
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := format.WriteJSON(f, s); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	chownToInvokingUser(path)
	return nil
}

// chownToInvokingUser hands a freshly-written output file back to the human who
// ran csd under sudo. Live mode needs root (ig needs CAP_BPF/CAP_PERFMON), so
// `sudo csd observe --out sidecar.json` creates the file root:root 0600 — and the
// invoking user then can't read their own evidence (or feed it to jq / the
// compose-lint contribution flow) without sudo (#209). When SUDO_UID/SUDO_GID are
// set, chown to them; 0600 is preserved, only ownership moves. A non-sudo
// invocation has no SUDO_UID and is left untouched. Best-effort by design: the
// file is already written, so a chown failure must not fail the run — it just
// leaves ownership as-is (no worse than before).
func chownToInvokingUser(path string) {
	uidStr, gidStr := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if uidStr == "" || gidStr == "" {
		return
	}
	uid, err1 := strconv.Atoi(uidStr)
	gid, err2 := strconv.Atoi(gidStr)
	if err1 != nil || err2 != nil {
		return
	}
	_ = os.Chown(path, uid, gid)
}
