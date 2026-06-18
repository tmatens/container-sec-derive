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

// TraceTcpGadget is the pinned ig trace_tcp gadget image — the v0.8 egress
// observer's signal source. Like the other gadgets it is tagged to
// PinnedIGVersion so the schema is fixed per release.
const TraceTcpGadget = "ghcr.io/inspektor-gadget/gadget/trace_tcp:" + PinnedIGVersion

// egressPipelineOpts bundles every input the v0.8 egress observe pipeline
// takes, mirroring devicePipelineOpts. The single signal source is trace_tcp
// (filtered to outbound connects); like devices it needs no mount/volume
// config.
type egressPipelineOpts struct {
	AggregateOpts aggregateOpts
	Fixture       string // trace_tcp NDJSON; empty → live ig
	IGBin         string
	Duration      time.Duration
	Workload      string // recorded on the sidecar + fed to egress confidence
}

// produceEgressObservation runs the fixture-or-live egress observe path
// end-to-end and returns a fully populated *Sidecar with the egress allowlist
// recommendation, egress_destinations evidence, trace_health, and egress
// confidence scored. It is the egress analog of produceDeviceObservation.
func produceEgressObservation(opts egressPipelineOpts, stderr io.Writer) (*Sidecar, error) {
	observedAt := time.Now().UTC()
	var (
		eg  *egressObservation
		err error
	)
	if opts.Fixture != "" {
		src, openErr := os.Open(opts.Fixture)
		if openErr != nil {
			return nil, fmt.Errorf("open fixture: %w", openErr)
		}
		defer src.Close()
		eg, err = aggregateEgress(src, opts.AggregateOpts)
	} else {
		noteWSL2IfDetected(stderr)
		if verr := checkIGVersion(opts.IGBin, stderr); verr != nil {
			return nil, verr
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()
		eg, err = observeEgress(ctx, opts.IGBin, opts.AggregateOpts, stderr)
	}
	if err != nil {
		var amb *ambiguousSelectionError
		if errors.As(err, &amb) {
			return nil, wrapCoded(ExitTargetAmbiguous, err)
		}
		return nil, err
	}

	s := egressToSidecar(eg, opts.AggregateOpts)
	s.ObservedAt = observedAt
	s.Workload = opts.Workload
	if opts.Fixture == "" {
		s.DurationSeconds = int(opts.Duration.Seconds())
	}
	computeEgressConfidence(s)
	return s, nil
}

// egressToSidecar assembles a *Sidecar from the egress observation. The
// capability/fs/device scaffolding is left at NewSidecar's empty defaults; the
// egress section (egress_destinations + egress_recommendation) carries the
// observation. PLAN.md §Output schema: one observer per run populates its block.
func egressToSidecar(eg *egressObservation, opts aggregateOpts) *Sidecar {
	s := NewSidecar()
	s.Target.Mode = opts.modeLabel()
	s.Target.Selector = opts.selector()
	s.Target.ReplicasObserved = len(eg.PerReplica)
	for rid, c := range eg.PerReplicaCount {
		s.Target.PerReplicaEventCounts[rid] = c
	}
	if opts.Image != "" {
		s.Image = opts.Image
	} else {
		s.Image = eg.Image
	}

	applyEgressFields(s, eg)

	s.TraceHealth.EventsRecorded = eg.EventCount
	s.TraceHealth.EventsDropped = eg.Dropped
	finaliseTraceHealth(&s.TraceHealth)
	return s
}

// applyEgressFields populates the egress section of s (egress_recommendation,
// egress_destinations, and replica_egress_disagreement) from the observation.
// Mirrors applyDeviceFields.
func applyEgressFields(s *Sidecar, eg *egressObservation) {
	rec := egressToRecommendation(eg.Dests)
	s.EgressRecommendation = &rec

	ed := make([]EgressDestination, 0, len(eg.Dests))
	for _, d := range eg.Dests {
		entry := EgressDestination{Addr: d.Addr, Port: d.Port, Version: d.Version}
		if st := eg.Stats[d.String()]; st != nil {
			entry.EventCount = st.eventCount
			entry.CommSamples = sortedKeys(st.commSamples)
		}
		ed = append(ed, entry)
	}
	s.EgressDestinations = ed

	// Cross-replica egress-set disagreement under --all-matching: any union
	// destination not observed on every replica. The egress analog of
	// ReplicaDeviceDisagreement; undefined (left empty) with <2 replicas. A
	// non-empty list means the workload exercised replicas unevenly — the union
	// allowlist permits destinations some replica never used.
	if len(eg.PerReplica) > 1 {
		perReplicaSets := make(map[string]map[string]struct{}, len(eg.PerReplica))
		for rid, dests := range eg.PerReplica {
			set := make(map[string]struct{}, len(dests))
			for _, d := range dests {
				set[d.String()] = struct{}{}
			}
			perReplicaSets[rid] = set
		}
		var dis []string
		for _, d := range eg.Dests {
			for _, set := range perReplicaSets {
				if _, ok := set[d.String()]; !ok {
					dis = append(dis, d.String())
					break
				}
			}
		}
		sort.Strings(dis)
		s.Target.ReplicaEgressDisagreement = dis
	}
}

// observeEgress spawns `ig run trace_tcp --output json` and aggregates outbound
// connects for the lifetime of ctx. It is observeDevices with aggregateEgress
// swapped in and the trace_tcp gadget — the same stderr-drain + ringbuf-loss
// accounting and early-error kill; only the gadget and classifier differ.
func observeEgress(ctx context.Context, igBin string, opts aggregateOpts, stderrSink io.Writer) (*egressObservation, error) {
	cmd := exec.CommandContext(ctx, igBin, "run", TraceTcpGadget, "--output", "json")
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

	obs, aggErr := aggregateEgress(stdout, opts)
	earlyErr := aggErr != nil && !errors.Is(aggErr, io.EOF)
	if earlyErr {
		// Undrained stdout on early error → ig blocks and never exits; kill it
		// so the stderr drain + cmd.Wait() don't stall for the window (matches
		// observe()/observeDevices()).
		_ = cmd.Process.Kill()
	}
	// Join the stderr drain BEFORE cmd.Wait() (StderrPipe contract).
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
