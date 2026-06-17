package main

import (
	"context"
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

// capaddPipelineOpts bundles every input the v0.5 dangerous-cap_add validator
// takes. Its signal source is trace_capabilities — the same gadget the v0.1 cap
// observer drives — so there is no second fixture (cf. privileged's
// DeviceFixture). ActiveSet is the validate-set (the explicit --cap-add set, or
// the dangerousCaps default); Granted records whether it came from --cap-add, the
// switch that enables unused-cap detection and the recommended minimized cap_add.
type capaddPipelineOpts struct {
	AggregateOpts aggregateOpts
	ActiveSet     map[string]struct{}
	Granted       bool
	Fixture       string // trace_capabilities NDJSON; empty -> live ig
	IGBin         string
	Duration      time.Duration
	Workload      string
}

// produceCapaddObservation runs the fixture-or-live capadd observe path
// end-to-end and returns a fully populated *Sidecar with the capadd_validation
// block, trace_health, and capadd confidence already scored. It is the v0.5
// analog of produceDeviceObservation: same fixture-vs-live branch shape and
// typed-exit translation, reusing the trace_capabilities stream.
func produceCapaddObservation(opts capaddPipelineOpts, stderr io.Writer) (*Sidecar, error) {
	observedAt := time.Now().UTC()
	var (
		obs *capaddObservation
		err error
	)
	if opts.Fixture != "" {
		src, openErr := os.Open(opts.Fixture)
		if openErr != nil {
			return nil, fmt.Errorf("open fixture: %w", openErr)
		}
		defer src.Close()
		obs, err = aggregateCapadd(src, opts.AggregateOpts, opts.ActiveSet)
	} else {
		noteWSL2IfDetected(stderr)
		if verr := checkIGVersion(opts.IGBin, stderr); verr != nil {
			return nil, verr
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()
		obs, err = observeCapadd(ctx, opts.IGBin, opts.AggregateOpts, opts.ActiveSet, stderr)
	}
	if err != nil {
		var amb *ambiguousSelectionError
		if errors.As(err, &amb) {
			return nil, wrapCoded(ExitTargetAmbiguous, err)
		}
		return nil, err
	}

	s := capaddToSidecar(obs, opts)
	s.ObservedAt = observedAt
	s.Workload = opts.Workload
	if opts.Fixture == "" {
		s.DurationSeconds = int(opts.Duration.Seconds())
	}
	computeCapaddConfidence(s)
	return s, nil
}

// capaddToSidecar assembles a *Sidecar from the capadd observation. The other
// observers' scaffolding is left at NewSidecar's empty defaults; the
// capadd_validation block carries the per-cap verdicts. ReplicaCapDisagreement is
// populated with the dangerous caps observed on fewer than all replicas (the
// capadd analog of the cap observer's same field), feeding the confidence rubric.
func capaddToSidecar(obs *capaddObservation, opts capaddPipelineOpts) *Sidecar {
	s := NewSidecar()
	s.Target.Mode = opts.AggregateOpts.modeLabel()
	s.Target.Selector = opts.AggregateOpts.selector()
	s.Target.ReplicasObserved = len(obs.PerReplica)
	for rid, c := range obs.PerReplicaCount {
		s.Target.PerReplicaEventCounts[rid] = c
	}
	if opts.AggregateOpts.Image != "" {
		s.Image = opts.AggregateOpts.Image
	} else {
		s.Image = obs.Image
	}

	s.CapaddValidation = capaddToValidation(obs, opts.ActiveSet, opts.Granted)

	// Cross-replica dangerous-cap disagreement under --all-matching: any cap
	// observed in use on some but not all replicas. Mirrors the device
	// observer's ReplicaDeviceDisagreement; undefined (left empty) with <2
	// replicas. A non-empty list means the workload exercised replicas
	// unevenly, so a per-replica validation would differ from the union.
	if len(obs.PerReplica) > 1 {
		perReplicaSets := make(map[string]map[string]struct{}, len(obs.PerReplica))
		union := map[string]struct{}{}
		for rid, caps := range obs.PerReplica {
			set := make(map[string]struct{}, len(caps))
			for _, c := range caps {
				set[c] = struct{}{}
				union[c] = struct{}{}
			}
			perReplicaSets[rid] = set
		}
		var dis []string
		for c := range union {
			for _, set := range perReplicaSets {
				if _, ok := set[c]; !ok {
					dis = append(dis, c)
					break
				}
			}
		}
		sort.Strings(dis)
		s.Target.ReplicaCapDisagreement = dis
	}

	s.TraceHealth.EventsRecorded = obs.EventCount
	s.TraceHealth.EventsDropped = obs.Dropped
	finaliseTraceHealth(&s.TraceHealth)
	return s
}

// observeCapadd spawns `ig run trace_capabilities --output json` and aggregates
// dangerous-cap usage for the lifetime of ctx. It is observe() with
// aggregateCapadd swapped in for aggregate() — the same gadget and the same
// stderr-drain + ringbuf-loss accounting; only the aggregation differs (keyed on
// syscall-per-cap rather than deduped to a cap set).
func observeCapadd(ctx context.Context, igBin string, opts aggregateOpts, activeSet map[string]struct{}, stderrSink io.Writer) (*capaddObservation, error) {
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
		wg   sync.WaitGroup
		lost int
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		lost = parseIGStderr(stderrPipe, stderrSink)
	}()

	obs, aggErr := aggregateCapadd(stdout, opts, activeSet)
	earlyErr := aggErr != nil && !errors.Is(aggErr, io.EOF)
	if earlyErr {
		// Undrained stdout on early error → ig blocks and never exits; kill it
		// so the stderr drain + cmd.Wait() don't stall for the window (matches
		// observe()).
		_ = cmd.Process.Kill()
	}
	// Join the stderr drain BEFORE cmd.Wait() (StderrPipe contract): the read
	// must finish before Wait closes the pipe, else a trailing `lost N` line
	// can be dropped.
	wg.Wait()
	waitErr := cmd.Wait()
	if earlyErr {
		return nil, aggErr
	}
	if waitErr != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("ig exited: %w", waitErr)
	}
	if obs != nil {
		obs.Dropped = lost
	}
	return obs, nil
}
