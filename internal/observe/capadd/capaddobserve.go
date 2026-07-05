package capadd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/ig"
	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/observe/caps"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// CapaddPipelineOpts bundles every input the v0.5 dangerous-cap_add validator
// takes. Its signal source is trace_capabilities — the same gadget the v0.1 cap
// observer drives — so there is no second fixture (cf. privileged's
// DeviceFixture). ActiveSet is the validate-set (the explicit --cap-add set, or
// the DangerousCaps default); Granted records whether it came from --cap-add, the
// switch that enables unused-cap detection and the recommended minimized cap_add.
type CapaddPipelineOpts struct {
	AggregateOpts attrib.Opts
	ActiveSet     map[string]struct{}
	Granted       bool
	Fixture       string // trace_capabilities NDJSON; empty -> live ig
	IGBin         string
	Duration      time.Duration
	Workload      string
	RuntimeBin    string // container CLI for the image-digest lookup (internal/runtime); empty → docker
}

// ProduceCapaddObservation runs the fixture-or-live capadd observe path
// end-to-end and returns a fully populated *Sidecar with the capadd_validation
// block, trace_health, and capadd confidence already scored. It is the v0.5
// analog of produceDeviceObservation: same fixture-vs-live branch shape and
// typed-exit translation, reusing the trace_capabilities stream.
func ProduceCapaddObservation(opts CapaddPipelineOpts, stderr io.Writer) (*sidecar.Sidecar, error) {
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
		obs, err = AggregateCapadd(src, opts.AggregateOpts, opts.ActiveSet)
	} else {
		observe.NoteWSL2IfDetected(stderr)
		if verr := ig.CheckIGVersion(opts.IGBin, stderr); verr != nil {
			return nil, verr
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()
		obs, err = observeCapadd(ctx, opts.IGBin, opts.AggregateOpts, opts.ActiveSet, stderr)
	}
	if err != nil {
		var amb *exit.AmbiguousSelectionError
		if errors.As(err, &amb) {
			return nil, exit.WrapCoded(exit.TargetAmbiguous, err)
		}
		return nil, err
	}

	s := capaddToSidecar(obs, opts)
	s.ObservedAt = observedAt
	s.Workload = opts.Workload
	if opts.Fixture == "" {
		s.DurationSeconds = int(opts.Duration.Seconds())
	}
	// Digest-pin for the compose-lint-profile contract (digest-only helper;
	// the capadd validator re-aggregates caps but does not observe an image's
	// entrypoint caps, so it uses the lightweight digest lookup).
	caps.PopulateImageDigest(s, opts.AggregateOpts.Container, opts.AggregateOpts.Image, opts.RuntimeBin, opts.Fixture != "", stderr)
	computeCapaddConfidence(s)
	return s, nil
}

// capaddToSidecar assembles a *Sidecar from the capadd observation. The other
// observers' scaffolding is left at NewSidecar's empty defaults; the
// capadd_validation block carries the per-cap verdicts. ReplicaCapDisagreement is
// populated with the dangerous caps observed on fewer than all replicas (the
// capadd analog of the cap observer's same field), feeding the confidence rubric.
func capaddToSidecar(obs *capaddObservation, opts CapaddPipelineOpts) *sidecar.Sidecar {
	s := sidecar.NewSidecar()
	s.Target.Mode = opts.AggregateOpts.ModeLabel()
	s.Target.Selector = opts.AggregateOpts.Selector()
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
	s.TraceHealth.Finalise()
	return s
}

// observeCapadd spawns `ig run trace_capabilities --output json` and aggregates
// dangerous-cap usage for the lifetime of ctx. It is observe() with
// AggregateCapadd swapped in for aggregate() — the same gadget and the same
// stderr-drain + ringbuf-loss accounting; only the aggregation differs (keyed on
// syscall-per-cap rather than deduped to a cap set).
func observeCapadd(ctx context.Context, igBin string, opts attrib.Opts, activeSet map[string]struct{}, stderrSink io.Writer) (*capaddObservation, error) {
	obs, lost, err := ig.RunGadget(ctx, igBin, ig.TraceCapabilitiesGadget, []string{"--output", "json"}, stderrSink,
		func(stdout io.Reader) (*capaddObservation, error) { return AggregateCapadd(stdout, opts, activeSet) })
	if err != nil {
		return nil, err
	}
	if obs != nil {
		obs.Dropped = lost
	}
	return obs, nil
}
