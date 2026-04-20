// csd — container-sec-derive.
//
// v0.1.0-alpha scope (PLAN.md): subprocess `ig run trace_capabilities`,
// parse line-delimited JSON events, filter to one container, print the
// distinct cap set to stdout, exit. No formatters, no sidecar, no verify.
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
	"syscall"
	"time"
)

// capEvent is the subset of ig trace_capabilities fields we consume.
// IG's full schema is larger; we decode only what the aggregator needs
// so a minor IG schema drift in unused fields doesn't break us.
type capEvent struct {
	Timestamp int64  `json:"timestamp"`
	Comm      string `json:"comm"`
	Pid       int    `json:"pid"`
	Syscall   string `json:"syscall"`
	CapName   string `json:"capName"`
	Cap       int    `json:"cap"`
	Container struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Image string `json:"image"`
	} `json:"container"`
}

// traceHealthEvent is IG's periodic ringbuf-health message. PLAN.md
// §Event-loss reporting requires these counters be surfaced on every
// run. Schema here is our best-effort; Step 11's IG version pin will
// lock it against an upstream release.
type traceHealthEvent struct {
	Type           string `json:"type"`
	EventsRecorded int    `json:"events_recorded"`
	EventsDropped  int    `json:"events_dropped"`
}

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
		if ev.Container.ID == o.Container || ev.Container.Name == o.Container {
			return true
		}
		if len(o.Container) >= 6 && strings.HasPrefix(ev.Container.ID, o.Container) {
			return true
		}
	}
	if o.Image != "" && ev.Container.Image == o.Image {
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
		duration     = fs.Duration("duration", 30*time.Second, "observation window (ignored in --fixture mode)")
		igBin        = fs.String("ig", "ig", "path to the ig binary")
		initWindowMs = fs.Int("init-window-ms", 500, "drop capability events observed within this many ms of the first matching event (0 disables)")
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

	opts := aggregateOpts{
		Container:    *container,
		Image:        *image,
		AllMatching:  *allMatching,
		InitWindowMs: *initWindowMs,
	}

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
	} else {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, *duration)
		defer timeoutCancel()
		s, err = observe(ctx, *igBin, opts)
		if s != nil {
			s.DurationSeconds = int(duration.Seconds())
		}
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

	computeConfidence(s)
	printCaps(stdout, s.CapNames())

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
// events for the lifetime of ctx.
func observe(ctx context.Context, igBin string, opts aggregateOpts) (*Sidecar, error) {
	cmd := exec.CommandContext(ctx, igBin, "run", "trace_capabilities", "--output", "json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		if isIGMissing(err) {
			return nil, wrapCoded(ExitIGMissing, fmt.Errorf("ig binary %q not available: %w", igBin, err))
		}
		return nil, fmt.Errorf("start %s: %w", igBin, err)
	}
	s, aggErr := aggregate(stdout, opts)
	// Wait for ig to exit. A context-cancel kill is the normal termination
	// path for the timed observation window, so we don't propagate that as
	// an error.
	waitErr := cmd.Wait()
	if aggErr != nil && !errors.Is(aggErr, io.EOF) {
		return nil, aggErr
	}
	if waitErr != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("ig exited: %w", waitErr)
	}
	return s, nil
}

// replicaState accumulates per-replica data as aggregate() streams events.
// Replica identity is the container id (falling back to name when id is
// empty, as happens in hand-authored test fixtures). Under live BPF this
// will be cgroup id -- see PLAN.md §Target selection for the attribution
// contract. Init-window filtering is per-replica because each replica has
// its own startup phase.
type replicaState struct {
	seen       map[string]struct{}
	comms      map[string]struct{} // post-init-window comms; feeds confidence rubric
	firstTsMs  int64
	firstSeen  bool
	suppressed int
	eventCount int
	sampleName string // for ambiguity-error messages
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
	var latestHealth *traceHealthEvent
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	for scan.Scan() {
		line := scan.Bytes()
		if len(line) == 0 {
			continue
		}
		// Type-discriminate: trace_health / diagnostic lines are decoded
		// first and never flow into the capability aggregator. Untagged
		// lines fall through to the capEvent path (IG emits cap events
		// without a "type" field at the pinned release).
		var env struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &env); err == nil && env.Type == "trace_health" {
			var th traceHealthEvent
			if err := json.Unmarshal(line, &th); err == nil {
				latestHealth = &th
			}
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
		rid := ev.Container.ID
		if rid == "" {
			rid = ev.Container.Name
		}
		st, ok := replicas[rid]
		if !ok {
			st = &replicaState{
				seen:       map[string]struct{}{},
				comms:      map[string]struct{}{},
				sampleName: ev.Container.Name,
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
		st.seen[name] = struct{}{}
		if c := strings.TrimSpace(ev.Comm); c != "" {
			st.comms[c] = struct{}{}
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

	union := map[string]struct{}{}
	commUnion := map[string]struct{}{}
	var totalSuppressed int
	for rid, st := range replicas {
		totalSuppressed += st.suppressed
		s.Target.PerReplicaEventCounts[rid] = st.eventCount
		s.Target.PerReplicaCaps[rid] = sortedStringSet(st.seen)
		for n := range st.seen {
			union[n] = struct{}{}
		}
		for c := range st.comms {
			commUnion[c] = struct{}{}
		}
	}
	s.Target.InitWindowSuppressed = totalSuppressed
	s.Target.DistinctComms = len(commUnion)

	allNames := sortedStringSet(union)
	for _, n := range allNames {
		s.Capabilities = append(s.Capabilities, Capability{Name: n})
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

	if latestHealth != nil {
		s.TraceHealth.EventsRecorded = latestHealth.EventsRecorded
		s.TraceHealth.EventsDropped = latestHealth.EventsDropped
		if latestHealth.EventsRecorded > 0 {
			s.TraceHealth.DropRate = float64(latestHealth.EventsDropped) / float64(latestHealth.EventsRecorded)
		}
	}
	// Confidence scoring is a separate, callable-from-tests step. Callers
	// (run/observe) populate DurationSeconds and any other late-arriving
	// inputs before invoking computeConfidence so the rubric sees the
	// final sidecar.
	return s, nil
}

func sortedStringSet(m map[string]struct{}) []string {
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

func printCaps(w io.Writer, caps []string) {
	for _, c := range caps {
		fmt.Fprintln(w, c)
	}
}
