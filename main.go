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

// Pinned IG release. v0.1 targets a single upstream version; MIN/MAX
// equal the pin until we've smoke-tested against a widening window.
// PLAN.md §IG version pinning defines the v1 semantics; v0.1-rc
// warn-and-continues on mismatch so we learn about drift without
// breaking fixture-only users.
const (
	PinnedIGVersion      = "v0.51.0"
	MinIGVersion         = "v0.51.0"
	MaxTestedIGVersion   = "v0.51.0"

	// TraceCapabilitiesGadget is the OCI reference ig pulls to run the
	// trace_capabilities gadget. ig v0.51.0 is fully image-based: a bare
	// "trace_capabilities" is not a valid argument to `ig run`. We tag to
	// PinnedIGVersion so the gadget image and the ig binary advance
	// together; bumping the pin means re-pulling this tag.
	TraceCapabilitiesGadget = "ghcr.io/inspektor-gadget/gadget/trace_capabilities:" + PinnedIGVersion
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
	Proc      struct {
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
		Proc         procT           `json:"proc"`
		Runtime      runtimeT        `json:"runtime"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	e.Syscall = wire.Syscall
	e.CapName = wire.CapName
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
	if o.Container == "" && o.Image == "" {
		return true
	}
	if o.Container != "" {
		if ev.Runtime.ContainerID == o.Container || ev.Runtime.ContainerName == o.Container {
			return true
		}
		if len(o.Container) >= 6 && strings.HasPrefix(ev.Runtime.ContainerID, o.Container) {
			return true
		}
	}
	if o.Image != "" && ev.Runtime.ContainerImage == o.Image {
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
	fs := flag.NewFlagSet("csd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		container    = fs.String("container", "", "target container id or name (mutually exclusive with --image)")
		image        = fs.String("image", "", "select containers by image reference (errors if >1 match without --all-matching)")
		allMatching  = fs.Bool("all-matching", false, "aggregate across all replicas matching --image")
		fixture      = fs.String("fixture", "", "read ig-format NDJSON from this file instead of spawning ig")
		fixtureErr   = fs.String("fixture-stderr", "", "fixture-mode only: file of ig stderr lines; drops parsed as if piped from live ig")
		duration     = fs.Duration("duration", 30*time.Second, "observation window (ignored in --fixture mode)")
		igBin        = fs.String("ig", "ig", "path to the ig binary")
		initWindowMs = fs.Int("init-window-ms", 500, "drop capability events observed within this many ms of the first matching event (0 disables)")
		outPath      = fs.String("out", "", "write canonical JSON evidence sidecar to this file (stdout still prints the chosen --format)")
		format       = fs.String("format", FormatCompose, "output format for stdout (implemented: compose, docker-run, json; still landing in v0.1.0-rc: compose-patch, oci, k8s, compose-lint-profile)")
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
	case FormatCompose, FormatDockerRun, FormatJSON:
		// implemented
	default:
		return codedErrorf(ExitUsage, "--format %q not implemented yet; supported: %s, %s, %s (compose-patch, oci, k8s, compose-lint-profile still landing in v0.1.0-rc)", *format, FormatCompose, FormatDockerRun, FormatJSON)
	}

	opts := aggregateOpts{
		Container:    *container,
		Image:        *image,
		AllMatching:  *allMatching,
		InitWindowMs: *initWindowMs,
	}

	observedAt := time.Now().UTC()

	var (
		s   *Sidecar
		err error
	)
	if *fixture != "" {
		src, openErr := os.Open(*fixture)
		if openErr != nil {
			return fmt.Errorf("open fixture: %w", openErr)
		}
		defer src.Close()
		s, err = aggregate(src, opts)
		// Fixture mode: duration is unknown, so leave DurationSeconds=0
		// (computeConfidence treats 0 as "not measured" and skips the
		// soft-floor check).
		if err == nil && s != nil && *fixtureErr != "" {
			errSrc, openErrErr := os.Open(*fixtureErr)
			if openErrErr != nil {
				return fmt.Errorf("open fixture-stderr: %w", openErrErr)
			}
			s.TraceHealth.EventsDropped = parseIGStderr(errSrc, nil)
			errSrc.Close()
		}
	} else {
		checkIGVersion(*igBin, stderr)
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, *duration)
		defer timeoutCancel()
		s, err = observe(ctx, *igBin, opts, stderr)
		if s != nil {
			s.DurationSeconds = int(duration.Seconds())
		}
	}
	if s != nil {
		finaliseTraceHealth(&s.TraceHealth)
	}
	if err != nil {
		// Map typed failures to their PLAN.md §Exit codes slot. Anything
		// already coded (e.g. ExitIGMissing from observe) is returned
		// verbatim.
		var amb *ambiguousSelectionError
		if errors.As(err, &amb) {
			return wrapCoded(ExitTargetAmbiguous, err)
		}
		return err
	}

	s.ObservedAt = observedAt
	computeConfidence(s)
	switch *format {
	case FormatCompose:
		if err := writeCompose(stdout, s); err != nil {
			return fmt.Errorf("write compose: %w", err)
		}
	case FormatDockerRun:
		if err := writeDockerRun(stdout, s); err != nil {
			return fmt.Errorf("write docker-run: %w", err)
		}
	case FormatJSON:
		if err := writeJSON(stdout, s); err != nil {
			return fmt.Errorf("write json: %w", err)
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
		wg      sync.WaitGroup
		lost    int
		lostMu  sync.Mutex
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

// checkIGVersion runs `ig version` and warns if the detected release
// is not PinnedIGVersion. ig v0.51.0 does not support --output json
// on `version`; the subcommand emits a single plain-text line like
// "v0.51.0". We take the first whitespace-delimited token so future
// ig releases that add trailing metadata still parse.
//
// v0.1-rc is warn-and-continue; PLAN.md §IG version pinning specifies
// v1 promotes this to a hard SchemaMismatch exit.
func checkIGVersion(igBin string, stderr io.Writer) {
	out, err := exec.Command(igBin, "version").Output()
	if err != nil {
		// ig may be absent; observe() will surface the proper exit
		// code. Only note it here if stderr is writable.
		if stderr != nil {
			fmt.Fprintf(stderr, "csd: ig version check skipped: %v\n", err)
		}
		return
	}
	var v struct {
		Version string
	}
	fields := strings.Fields(string(out))
	if len(fields) > 0 {
		v.Version = fields[0]
	}
	if v.Version == "" {
		return
	}
	if v.Version != PinnedIGVersion && stderr != nil {
		fmt.Fprintf(stderr,
			"csd: warning: ig %s detected, PINNED_IG_VERSION=%s (tested window %s..%s). Parsing may misalign; see PLAN.md §IG version pinning.\n",
			v.Version, PinnedIGVersion, MinIGVersion, MaxTestedIGVersion,
		)
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
