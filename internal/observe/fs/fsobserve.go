package fs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/ig"
	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// FSPipelineOpts bundles every input the v0.2 read-only-filesystem observe
// pipeline takes, mirroring PipelineOpts for the capability path. The
// fs observer's two signal sources are trace_open (write-intent paths) and the
// container's mount config (volume correlation); MountsFixture supplies the
// latter hermetically, the same way Fixture supplies trace_open NDJSON.
type FSPipelineOpts struct {
	AggregateOpts attrib.Opts
	Fixture       string // trace_open NDJSON; empty → live ig
	MountsFixture string // <runtime>-inspect .Mounts JSON; empty → live inspect (or none in fixture mode)
	IGBin         string
	RuntimeBin    string // container CLI for `inspect .Mounts` (internal/runtime); empty → docker
	Duration      time.Duration
	Workload      string // --workload path recorded on the sidecar + fed to fs confidence
	// GadgetFilter pushes an in-gadget --containername filter for a
	// --container target (see observe.GadgetContainerFilter). Opt-in: on
	// some runtime/ig combinations the filter matches nothing and the run
	// observes zero events.
	GadgetFilter bool
}

// ProduceFSObservation runs the fixture-or-live fs observe path end-to-end and
// returns a fully populated *Sidecar with the read_only/tmpfs recommendation,
// writable_paths evidence, trace_health, and fs confidence already scored. It
// is the fs-observer analog of ProduceObservation: same fixture-vs-live branch
// shape (fixture short-circuits to aggregateWrites before the live-only ig
// version check), same typed-exit translation. The write paths come from
// trace_open; the mount config comes from acquireMounts; fsToSidecar joins them.
//
// Scope (issue #77): multi-replica fs correlation under --image is deferred to
// PR-C; see acquireMounts.
func ProduceFSObservation(opts FSPipelineOpts, stderr io.Writer) (*sidecar.Sidecar, error) {
	observedAt := time.Now().UTC()
	var (
		writes *writeObservation
		err    error
	)
	if opts.Fixture != "" {
		src, openErr := os.Open(opts.Fixture)
		if openErr != nil {
			return nil, fmt.Errorf("open fixture: %w", openErr)
		}
		defer src.Close()
		writes, err = aggregateWrites(src, opts.AggregateOpts)
	} else {
		observe.NoteWSL2IfDetected(stderr)
		if verr := ig.CheckIGVersion(opts.IGBin, stderr); verr != nil {
			return nil, verr
		}
		// Resolve the in-gadget filter BEFORE the observation window opens:
		// the runtime inspect must not spend the caller's --duration.
		var filter []string
		if opts.GadgetFilter {
			filter = observe.GadgetContainerFilter(opts.AggregateOpts.Container, opts.RuntimeBin, opts.IGBin, stderr)
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()
		writes, err = observeWrites(ctx, opts.IGBin, filter, opts.AggregateOpts, stderr)
	}
	if err != nil {
		var amb *exit.AmbiguousSelectionError
		if errors.As(err, &amb) {
			return nil, exit.WrapCoded(exit.TargetAmbiguous, err)
		}
		return nil, err
	}

	mounts, err := acquireMounts(opts, observe.SortedKeys(writes.PerReplica), stderr)
	if err != nil {
		return nil, err
	}
	s := fsToSidecar(writes, mounts, opts.AggregateOpts)
	s.ObservedAt = observedAt
	s.Workload = opts.Workload
	if opts.Fixture == "" {
		// Fixture mode: duration unknown, leave 0 (computeFSConfidence treats
		// 0 as "not measured" and skips the soft floor).
		s.DurationSeconds = int(opts.Duration.Seconds())
	}
	// Digest-pin so the compose-lint-profile contract can reference the exact
	// artifact. fs never observes caps, so this uses the digest-only helper
	// rather than the caps entrypoint cross-check.
	observe.PopulateImageDigest(s, opts.AggregateOpts.Container, opts.AggregateOpts.Image, opts.RuntimeBin, opts.Fixture != "", stderr)
	computeFSConfidence(s)
	return s, nil
}

// fsToSidecar assembles a *Sidecar from the write observation and the mount
// config. The capability scaffolding (Capabilities/ExpectedCaps/...) is left at
// NewSidecar's empty defaults; the fs section (writable_paths +
// fs_recommendation) carries the observation. PLAN.md §Output schema: one
// observer per run populates its own block.
func fsToSidecar(writes *writeObservation, mounts []string, opts attrib.Opts) *sidecar.Sidecar {
	s := sidecar.NewSidecar()
	s.Target.Mode = opts.ModeLabel()
	s.Target.Selector = opts.Selector()
	s.Target.ReplicasObserved = len(writes.PerReplica)
	for rid, c := range writes.PerReplicaCount {
		s.Target.PerReplicaEventCounts[rid] = c
	}
	if opts.Image != "" {
		s.Image = opts.Image
	} else {
		s.Image = writes.Image
	}

	rec := correlateWrites(writes.Paths, mounts)
	s.FSRecommendation = &rec

	wp := make([]sidecar.WritablePath, 0, len(writes.Paths))
	for _, p := range writes.Paths {
		disp := sidecar.DispositionTmpfsCandidate
		if underAnyMount(p, mounts) {
			disp = sidecar.DispositionVolumeCovered
		}
		entry := sidecar.WritablePath{Path: p, Disposition: disp}
		if st := writes.Stats[p]; st != nil {
			entry.EventCount = st.eventCount
			entry.CommSamples = observe.SortedKeys(st.commSamples)
		}
		wp = append(wp, entry)
	}
	s.WritablePaths = wp

	// Cross-replica write-path disagreement under --all-matching: any union
	// path not observed on every replica. The fs analog of
	// ReplicaCapDisagreement; undefined (left empty) with <2 replicas. Feeds
	// computeFSConfidence. A non-empty list means the workload exercised
	// replicas unevenly — the union recommendation includes tmpfs paths some
	// replica never wrote, which a reviewer should weigh.
	if len(writes.PerReplica) > 1 {
		perReplicaSets := make(map[string]map[string]struct{}, len(writes.PerReplica))
		for rid, paths := range writes.PerReplica {
			set := make(map[string]struct{}, len(paths))
			for _, p := range paths {
				set[p] = struct{}{}
			}
			perReplicaSets[rid] = set
		}
		var dis []string
		for _, p := range writes.Paths {
			for _, set := range perReplicaSets {
				if _, ok := set[p]; !ok {
					dis = append(dis, p)
					break
				}
			}
		}
		sort.Strings(dis)
		s.Target.ReplicaWritePathDisagreement = dis
	}

	s.TraceHealth.EventsRecorded = writes.EventCount
	s.TraceHealth.EventsDropped = writes.Dropped
	s.TraceHealth.Finalise()
	return s
}

// observeWrites spawns `ig run trace_open --paths --output json` and aggregates
// write-intent opens for the lifetime of ctx. It mirrors observe() (the cap
// path) but against the trace_open gadget: --paths makes ig emit the
// symlink-resolved fpath (FileEvent.Path prefers it). ig's stderr is drained
// through parseIGStderr so it can't block the pipe and its diagnostics still
// reach the operator; the ringbuf-loss count it returns lands on
// writeObservation.Dropped and feeds trace_health.
func observeWrites(ctx context.Context, igBin string, filterArgs []string, opts attrib.Opts, stderrSink io.Writer) (*writeObservation, error) {
	args := append(append([]string{}, filterArgs...), "--paths", "--output", "json")
	obs, lost, err := ig.RunGadget(ctx, igBin, ig.TraceOpenGadget, args, stderrSink,
		func(stdout io.Reader) (*writeObservation, error) { return aggregateWrites(stdout, opts) })
	if err != nil {
		return nil, err
	}
	if obs != nil {
		obs.Dropped = lost
	}
	return obs, nil
}

// containerMount is the one field csd reads from a `docker inspect` mount
// record: the in-container path the volume/bind is mounted at. Writes at or
// below a Destination are volume-covered (correlateWrites), so they don't
// become tmpfs candidates.
type containerMount struct {
	Destination string `json:"Destination"`
}

// acquireMounts resolves the mount destinations for volume correlation, from
// (in order): an explicit --mounts-fixture, else live `docker inspect`, else
// nothing. observedReplicas are the container ids the observation actually saw
// (writeObservation.PerReplica keys), used to inspect the right containers
// under --image without re-resolving the selector.
//
// Live acquisition:
//   - --container: inspect that one target.
//   - --image (one or, under --all-matching, several replicas): inspect each
//     observed replica container and union their mount destinations, so a path
//     under any replica's volume is volume-covered. Replicas of one compose
//     service usually share mount topology, but unioning is the safe choice —
//     it never misclassifies a volume-backed write as a tmpfs candidate.
//
// No mounts are returned (every rootfs write becomes a tmpfs candidate) in
// hermetic fixture mode without --mounts-fixture, or when no replica id is
// available to inspect.
func acquireMounts(opts FSPipelineOpts, observedReplicas []string, stderr io.Writer) ([]string, error) {
	if opts.MountsFixture != "" {
		return loadMountsFixture(opts.MountsFixture)
	}
	if opts.Fixture != "" {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), observe.InspectDefaultTimeout)
	defer cancel()

	if opts.AggregateOpts.Container != "" {
		return mountDestinations(ctx, opts.AggregateOpts.Container, opts.RuntimeBin)
	}

	// --image: inspect each observed replica and union mount destinations.
	if len(observedReplicas) == 0 {
		if stderr != nil {
			fmt.Fprintln(stderr, "csd: note: no replica observed; mount correlation skipped, every rootfs write treated as a tmpfs candidate")
		}
		return nil, nil
	}
	union := map[string]struct{}{}
	for _, rid := range observedReplicas {
		dests, err := mountDestinations(ctx, rid, opts.RuntimeBin)
		if err != nil {
			return nil, err
		}
		for _, d := range dests {
			union[d] = struct{}{}
		}
	}
	return observe.SortedKeys(union), nil
}

// mountDestinations runs `<runtime> inspect --format '{{json .Mounts}}'` for the
// container and returns its sorted, non-empty mount destinations. runtimeBin is
// the container CLI (`docker`/`podman`, internal/runtime); empty defaults to
// docker. The command + template are docker-compatible across both.
func mountDestinations(ctx context.Context, container, runtimeBin string) ([]string, error) {
	if runtimeBin == "" {
		runtimeBin = "docker"
	}
	// "--" terminates flag parsing so a container id/name beginning with "-"
	// can't be smuggled in as a runtime flag (deep-review L2; defense-in-depth).
	out, err := exec.CommandContext(ctx, runtimeBin, "inspect", "--format", "{{json .Mounts}}", "--", container).Output()
	if err != nil {
		return nil, fmt.Errorf("%s inspect %s mounts: %w", runtimeBin, container, err)
	}
	return parseMountDestinations(out)
}

// loadMountsFixture reads a pre-captured `docker inspect .Mounts` JSON array
// from path. Used by --mounts-fixture for hermetic tests and CI runs without a
// docker daemon, mirroring loadInspectionFixture for the entrypoint check.
func loadMountsFixture(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mounts fixture %s: %w", path, err)
	}
	return parseMountDestinations(data)
}

// parseMountDestinations decodes a `docker inspect .Mounts` JSON array and
// returns the sorted, de-duplicated, non-empty Destination paths.
func parseMountDestinations(data []byte) ([]string, error) {
	data = bytes.TrimSpace(data)
	// `docker inspect` emits the JSON literal `null` for a container with no
	// mounts; treat it as the empty set rather than a parse error.
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil, nil
	}
	var ms []containerMount
	if err := json.Unmarshal(data, &ms); err != nil {
		return nil, fmt.Errorf("parse docker inspect .Mounts: %w", err)
	}
	seen := map[string]struct{}{}
	for _, m := range ms {
		if m.Destination != "" {
			seen[m.Destination] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}
