package caps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/ig"
	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// CapEvent is the subset of ig trace_capabilities fields we consume at
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
type CapEvent struct {
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

func (e *CapEvent) UnmarshalJSON(data []byte) error {
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
	e.Syscall = ig.NormalizeSyscall(wire.Syscall)
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

// Match reports whether a capability event belongs to the selected
// target. It lives here rather than on attrib.Opts because attrib must stay
// event-type-agnostic (it would otherwise have to import the caps event type);
// the generic string-level decision is attrib.Opts.MatchesRuntime.
func Match(o attrib.Opts, ev CapEvent) bool {
	return o.MatchesRuntime(ev.Runtime.ContainerID, ev.Runtime.ContainerName, ev.Runtime.ContainerImage)
}

// PipelineOpts bundles every input the fixture-or-live observe
// pipeline takes. Step 23 introduced the helper so `csd verify`'s
// run-mode can produce the verify-time observation without duplicating
// the observe→finalise→cross-check→confidence sequence from run().
//
// Composition: AggregateOpts carries the per-event-stream knobs
// (container/image selectors, init-window). The remaining fields are
// the wrapping concerns (where the events come from, where digests
// come from, how long the live window runs, the workload script
// recorded on the sidecar).
type PipelineOpts struct {
	AggregateOpts  attrib.Opts
	Fixture        string
	FixtureStderr  string
	InspectFixture string
	IGBin          string
	RuntimeBin     string // container CLI for inspect/history (internal/runtime); empty → docker
	Duration       time.Duration
	Workload       string
}

// ProduceObservation runs the fixture-or-live observe path end-to-end
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
func ProduceObservation(opts PipelineOpts, stderr io.Writer) (*sidecar.Sidecar, error) {
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
		s, err = Aggregate(src, opts.AggregateOpts)
		// Fixture mode: duration is unknown, so leave DurationSeconds=0
		// (ComputeConfidence treats 0 as "not measured" and skips the
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
		observe.NoteWSL2IfDetected(stderr)
		if verr := ig.CheckIGVersion(opts.IGBin, stderr); verr != nil {
			return nil, verr
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()
		s, err = Observe(ctx, opts.IGBin, opts.AggregateOpts, stderr)
		if s != nil {
			s.DurationSeconds = int(opts.Duration.Seconds())
		}
	}
	if s != nil {
		s.TraceHealth.Finalise()
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
	ApplyEntrypointCrossCheck(s, opts.InspectFixture, opts.RuntimeBin, opts.Fixture != "", stderr)
	// Live digest fallback: the cross-check pins the digest only from an
	// --inspect-fixture or a resolvable-tag image name; this robust lookup
	// (via the container's image ID) fills the gap for a live run. No-op when
	// the cross-check already pinned.
	observe.PopulateImageDigest(s, opts.AggregateOpts.Container, opts.AggregateOpts.Image, opts.RuntimeBin, opts.Fixture != "", stderr)
	ComputeConfidence(s)
	return s, nil
}

// Observe spawns `ig run trace_capabilities --output json` through the
// internal/ig signal seam and aggregates events for the lifetime of ctx.
// RunGadget drains ig's stderr so the ringbuf-loss counter (v0.51.0 emits these
// as stderr warnings, not typed stdout events) lands on the sidecar.
func Observe(ctx context.Context, igBin string, opts attrib.Opts, stderrSink io.Writer) (*sidecar.Sidecar, error) {
	s, lost, err := ig.RunGadget(ctx, igBin, ig.TraceCapabilitiesGadget, []string{"--output", "json"}, stderrSink,
		func(stdout io.Reader) (*sidecar.Sidecar, error) { return Aggregate(stdout, opts) })
	if err != nil {
		return nil, err
	}
	if s != nil {
		s.TraceHealth.EventsDropped = lost
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
func Aggregate(r io.Reader, opts attrib.Opts) (*sidecar.Sidecar, error) {
	replicas := map[string]*replicaState{}
	capUnion := map[string]*capStats{}
	var recorded int
	var globalFirstTsMs int64
	globalFirstSeen := false
	if err := observe.IterateNDJSON(r, func(line []byte) error {
		var ev CapEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			// Hard-fail on a malformed line, matching the fs/device/capadd
			// aggregators (deep-review L3). Silently skipping would yield a
			// SMALLER derived cap set with no signal — the dangerous direction,
			// since a user could then drop a cap the workload needs. The pinned
			// ig version (enforced by checkIGVersion) emits one clean JSON event
			// per stdout line, so a parse failure means corrupt input, not a
			// benign diagnostic line.
			return fmt.Errorf("parse trace_capabilities event: %w", err)
		}
		if !Match(opts, ev) {
			return nil
		}
		recorded++
		// Capable=false events are kretprobe-recorded denials: the
		// kernel asked, the LSM said no. PLAN.md §IG vs Tracee — we
		// only want held caps in the derived set. Counted toward
		// events_recorded so drop_rate's denominator reflects every
		// real ig sample we parsed.
		if !ev.Capable {
			return nil
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
		if IsInitComm(ev.Proc.Comm) {
			st.suppressed++
			return nil
		}
		if opts.InitWindowMs > 0 && ev.Timestamp-st.firstTsMs < int64(opts.InitWindowMs) {
			st.suppressed++
			return nil
		}
		name := NormalizeCap(ev.CapName)
		if name == "" {
			return nil
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
		return nil
	}); err != nil {
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
		s.Target.PerReplicaCaps[rid] = observe.SortedKeys(st.seen)
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

	allNames := observe.SortedKeys(capUnion)
	for _, n := range allNames {
		cs := capUnion[n]
		cap := sidecar.Capability{
			Name:        n,
			EventCount:  cs.eventCount,
			CommSamples: observe.SortedKeys(cs.commSamples),
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
	// inputs before invoking ComputeConfidence so the rubric sees the
	// final sidecar.
	return s, nil
}

// NormalizeCap strips the CAP_ prefix so output is consistent regardless
// of whether IG emits "CAP_NET_RAW" or "NET_RAW" for a given release.
func NormalizeCap(name string) string {
	name = strings.ToUpper(strings.TrimSpace(name))
	return strings.TrimPrefix(name, "CAP_")
}

// IsInitComm reports whether comm names a container-init process whose
// capability checks belong to runc/init bring-up rather than the user's
// workload. v0.1-rc only filters runc:[*] (e.g. "runc:[2:INIT]"); other
// init shapes (containerd-shim, crio-init) are out of scope until they
// surface on a reference image.
func IsInitComm(comm string) bool {
	return strings.HasPrefix(comm, "runc:")
}
