package main

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
	"sync"
	"syscall"
	"time"
)

// fsPipelineOpts bundles every input the v0.2 read-only-filesystem observe
// pipeline takes, mirroring observePipelineOpts for the capability path. The
// fs observer's two signal sources are trace_open (write-intent paths) and the
// container's mount config (volume correlation); MountsFixture supplies the
// latter hermetically, the same way Fixture supplies trace_open NDJSON.
type fsPipelineOpts struct {
	AggregateOpts aggregateOpts
	Fixture       string // trace_open NDJSON; empty → live ig
	MountsFixture string // docker-inspect .Mounts JSON; empty → live docker inspect (or none in fixture mode)
	IGBin         string
	Duration      time.Duration
}

// produceFSObservation runs the fixture-or-live fs observe path end-to-end and
// returns the read_only/tmpfs recommendation. It is the fs-observer analog of
// produceObservation: same fixture-vs-live branch shape (fixture short-circuits
// to aggregateWrites before the live-only ig version check), same typed-exit
// translation. The write paths come from trace_open; the mount config comes
// from acquireMounts; correlateWrites joins them into the recommendation.
//
// Scope (issue #77, this increment): the sidecar + confidence integration and
// the remaining six formatters are deliberately not here — this wires the pure
// core (fileevent/fsdecision/fsformat) to live signal sources for the compose
// formatter only. Multi-replica fs correlation under --image is also deferred;
// see acquireMounts.
func produceFSObservation(opts fsPipelineOpts, stderr io.Writer) (fsRecommendation, error) {
	var (
		writes *writeObservation
		err    error
	)
	if opts.Fixture != "" {
		src, openErr := os.Open(opts.Fixture)
		if openErr != nil {
			return fsRecommendation{}, fmt.Errorf("open fixture: %w", openErr)
		}
		defer src.Close()
		writes, err = aggregateWrites(src, opts.AggregateOpts)
	} else {
		noteWSL2IfDetected(stderr)
		if verr := checkIGVersion(opts.IGBin, stderr); verr != nil {
			return fsRecommendation{}, verr
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()
		writes, err = observeWrites(ctx, opts.IGBin, opts.AggregateOpts, stderr)
	}
	if err != nil {
		var amb *ambiguousSelectionError
		if errors.As(err, &amb) {
			return fsRecommendation{}, wrapCoded(ExitTargetAmbiguous, err)
		}
		return fsRecommendation{}, err
	}

	mounts, err := acquireMounts(opts, stderr)
	if err != nil {
		return fsRecommendation{}, err
	}
	return correlateWrites(writes.Paths, mounts), nil
}

// observeWrites spawns `ig run trace_open --paths --output json` and aggregates
// write-intent opens for the lifetime of ctx. It mirrors observe() (the cap
// path) but against the trace_open gadget: --paths makes ig emit the
// symlink-resolved fpath (fileEvent.Path prefers it). ig's stderr is drained
// through parseIGStderr so it can't block the pipe and its diagnostics still
// reach the operator; the ringbuf-loss count is discarded here because the
// writeObservation aggregate carries no trace_health yet — drop-rate accounting
// arrives with the sidecar/confidence follow-on (issue #77).
func observeWrites(ctx context.Context, igBin string, opts aggregateOpts, stderrSink io.Writer) (*writeObservation, error) {
	cmd := exec.CommandContext(ctx, igBin, "run", TraceOpenGadget, "--paths", "--output", "json")
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

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		parseIGStderr(stderrPipe, stderrSink)
	}()

	obs, aggErr := aggregateWrites(stdout, opts)
	// A context-cancel kill is the normal end of the timed window, so a
	// resulting wait error is not propagated (matches observe()).
	waitErr := cmd.Wait()
	wg.Wait()
	if aggErr != nil && !errors.Is(aggErr, io.EOF) {
		return nil, aggErr
	}
	if waitErr != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("ig exited: %w", waitErr)
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

// acquireMounts resolves the container's mount destinations for volume
// correlation, from (in order): an explicit --mounts-fixture, else a live
// `docker inspect` of the --container target, else nothing.
//
// Two cases return no mounts (so every rootfs write becomes a tmpfs candidate):
//   - Hermetic fixture mode (--fixture) without --mounts-fixture: there is no
//     container to inspect, and inventing mounts would be wrong.
//   - --image selection: `docker inspect <image>` has no .Mounts, and resolving
//     the per-replica container set + correlating each replica's own mounts is
//     the deferred multi-replica fs work (issue #77). We skip with a note
//     rather than silently inspect a wrong ref.
func acquireMounts(opts fsPipelineOpts, stderr io.Writer) ([]string, error) {
	if opts.MountsFixture != "" {
		return loadMountsFixture(opts.MountsFixture)
	}
	if opts.Fixture != "" {
		return nil, nil
	}
	if opts.AggregateOpts.Container == "" {
		if stderr != nil {
			fmt.Fprintln(stderr, "csd: note: --observe fs mount correlation is skipped under --image (per-replica correlation is a follow-on); every rootfs write is treated as a tmpfs candidate")
		}
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), inspectDefaultTimeout)
	defer cancel()
	return mountDestinations(ctx, opts.AggregateOpts.Container)
}

// mountDestinations runs `docker inspect --format '{{json .Mounts}}'` for the
// container and returns its sorted, non-empty mount destinations. Runtime is
// hardcoded to docker in this increment, matching inspectEntrypoint.
func mountDestinations(ctx context.Context, container string) ([]string, error) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{json .Mounts}}", container).Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect %s mounts: %w", container, err)
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
