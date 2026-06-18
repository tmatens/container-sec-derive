package egress

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

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/ig"
	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// EgressPipelineOpts bundles every input the v0.8 egress observe pipeline
// takes, mirroring devicePipelineOpts. The single signal source is trace_tcp
// (filtered to outbound connects); like devices it needs no mount/volume
// config.
type EgressPipelineOpts struct {
	AggregateOpts attrib.Opts
	Fixture       string // trace_tcp NDJSON; empty → live ig
	DNSFixture    string // trace_dns NDJSON for the DNS/hostname correlation (#159); empty → no DNS enrichment in fixture mode
	IGBin         string
	Duration      time.Duration
	Workload      string // recorded on the sidecar + fed to egress confidence
}

// ProduceEgressObservation runs the fixture-or-live egress observe path
// end-to-end and returns a fully populated *Sidecar with the egress allowlist
// recommendation, egress_destinations evidence, trace_health, and egress
// confidence scored. It is the egress analog of produceDeviceObservation.
func ProduceEgressObservation(opts EgressPipelineOpts, stderr io.Writer) (*sidecar.Sidecar, error) {
	observedAt := time.Now().UTC()
	var (
		eg   *egressObservation
		corr *dnsCorrelation // DNS/hostname correlation (#159); nil → TCP-only v0.5.0 shape
		err  error
	)
	if opts.Fixture != "" {
		// Fixture mode: trace_tcp from --fixture, trace_dns from the optional
		// --dns-fixture. An absent DNS half leaves corr nil (graceful degradation).
		src, openErr := os.Open(opts.Fixture)
		if openErr != nil {
			return nil, fmt.Errorf("open fixture: %w", openErr)
		}
		defer src.Close()
		eg, err = aggregateEgress(src, opts.AggregateOpts)
		if err == nil && opts.DNSFixture != "" {
			dnsSrc, openErr := os.Open(opts.DNSFixture)
			if openErr != nil {
				return nil, fmt.Errorf("open dns fixture: %w", openErr)
			}
			defer dnsSrc.Close()
			corr, err = aggregateDNS(dnsSrc, opts.AggregateOpts)
		}
	} else {
		// Live mode: trace_tcp + trace_dns run concurrently for one window, each
		// its own ig subprocess (mirrors the privileged observer's two-gadget
		// path). The trace_tcp error is fatal — it owns the allowlist. A trace_dns
		// error is non-fatal enrichment: it is surfaced on stderr and the run
		// continues with no correlation (the IP allowlist is unaffected; the
		// "no DNS observed" confidence factor then fires).
		observe.NoteWSL2IfDetected(stderr)
		if verr := ig.CheckIGVersion(opts.IGBin, stderr); verr != nil {
			return nil, verr
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()

		var (
			wg            sync.WaitGroup
			egErr, dnsErr error
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			eg, egErr = observeEgress(ctx, opts.IGBin, opts.AggregateOpts, stderr)
		}()
		go func() {
			defer wg.Done()
			corr, dnsErr = observeDNS(ctx, opts.IGBin, opts.AggregateOpts, stderr)
		}()
		wg.Wait()
		err = egErr
		if dnsErr != nil && egErr == nil {
			fmt.Fprintf(stderr, "csd: egress DNS correlation skipped (no hostnames/resolver this run): %v\n", dnsErr)
			corr = nil
		}
	}
	if err != nil {
		var amb *exit.AmbiguousSelectionError
		if errors.As(err, &amb) {
			return nil, exit.WrapCoded(exit.TargetAmbiguous, err)
		}
		return nil, err
	}

	s := egressToSidecar(eg, corr, opts.AggregateOpts)
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
func egressToSidecar(eg *egressObservation, corr *dnsCorrelation, opts attrib.Opts) *sidecar.Sidecar {
	s := sidecar.NewSidecar()
	s.Target.Mode = opts.ModeLabel()
	s.Target.Selector = opts.Selector()
	s.Target.ReplicasObserved = len(eg.PerReplica)
	for rid, c := range eg.PerReplicaCount {
		s.Target.PerReplicaEventCounts[rid] = c
	}
	if opts.Image != "" {
		s.Image = opts.Image
	} else {
		s.Image = eg.Image
	}

	applyEgressFields(s, eg, corr)

	s.TraceHealth.EventsRecorded = eg.EventCount
	s.TraceHealth.EventsDropped = eg.Dropped
	s.TraceHealth.Finalise()
	return s
}

// applyEgressFields populates the egress section of s (egress_recommendation,
// egress_destinations, and replica_egress_disagreement) from the observation.
// Mirrors applyDeviceFields.
func applyEgressFields(s *sidecar.Sidecar, eg *egressObservation, corr *dnsCorrelation) {
	rec := egressToRecommendation(eg.Dests)
	// DNS resolvers (UDP/53) are the destinations trace_tcp cannot see; a
	// default-DROP allowlist must permit them or name resolution breaks. Kept
	// separate from the TCP allowlist (different protocol). nil-safe.
	if corr != nil {
		rec.Resolvers = corr.Resolvers
	}
	s.EgressRecommendation = &rec

	ed := make([]sidecar.EgressDestination, 0, len(eg.Dests))
	for _, d := range eg.Dests {
		entry := sidecar.EgressDestination{Addr: d.Addr, Port: d.Port, Version: d.Version}
		entry.Hostnames = corr.HostnamesFor(d.Addr) // nil-safe; annotates the IP with its names
		if st := eg.Stats[d.String()]; st != nil {
			entry.EventCount = st.eventCount
			entry.CommSamples = observe.SortedKeys(st.commSamples)
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
func observeEgress(ctx context.Context, igBin string, opts attrib.Opts, stderrSink io.Writer) (*egressObservation, error) {
	cmd := exec.CommandContext(ctx, igBin, "run", ig.TraceTcpGadget, "--output", "json")
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
