package devices

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
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// DevicePipelineOpts bundles every input the v0.3 device-decomposition observe
// pipeline takes, mirroring fsPipelineOpts. The device observer's single signal
// source is trace_open (filtered to non-default /dev nodes); unlike the fs
// observer it needs no mount config — a device grant is not volume-correlated —
// so there is no MountsFixture analog.
type DevicePipelineOpts struct {
	AggregateOpts attrib.Opts
	Fixture       string // trace_open NDJSON; empty → live ig
	IGBin         string
	Duration      time.Duration
	Workload      string // --workload path recorded on the sidecar + fed to device confidence
	RuntimeBin    string // container CLI for the image-digest lookup (internal/runtime); empty → docker
}

// ProduceDeviceObservation runs the fixture-or-live device observe path
// end-to-end and returns a fully populated *Sidecar with the device
// recommendation, device_paths evidence, trace_health, and device confidence
// already scored. It is the device-observer analog of produceFSObservation:
// same fixture-vs-live branch shape and typed-exit translation. The device
// nodes come from trace_open; deviceToSidecar assembles the artifact.
func ProduceDeviceObservation(opts DevicePipelineOpts, stderr io.Writer) (*sidecar.Sidecar, error) {
	observedAt := time.Now().UTC()
	var (
		dev *DeviceObservation
		err error
	)
	if opts.Fixture != "" {
		src, openErr := os.Open(opts.Fixture)
		if openErr != nil {
			return nil, fmt.Errorf("open fixture: %w", openErr)
		}
		defer src.Close()
		dev, err = AggregateDevices(src, opts.AggregateOpts)
	} else {
		observe.NoteWSL2IfDetected(stderr)
		if verr := ig.CheckIGVersion(opts.IGBin, stderr); verr != nil {
			return nil, verr
		}
		// Resolve the in-gadget filter BEFORE the observation window opens:
		// the runtime inspect must not spend the caller's --duration.
		filter := observe.GadgetContainerFilter(opts.AggregateOpts.Container, opts.RuntimeBin, opts.IGBin, stderr)
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()
		dev, err = ObserveDevices(ctx, opts.IGBin, filter, opts.AggregateOpts, stderr)
	}
	if err != nil {
		var amb *exit.AmbiguousSelectionError
		if errors.As(err, &amb) {
			return nil, exit.WrapCoded(exit.TargetAmbiguous, err)
		}
		return nil, err
	}

	s := deviceToSidecar(dev, opts.AggregateOpts)
	s.ObservedAt = observedAt
	s.Workload = opts.Workload
	if opts.Fixture == "" {
		s.DurationSeconds = int(opts.Duration.Seconds())
	}
	// Digest-pin for the compose-lint-profile contract (digest-only helper;
	// devices never observes caps).
	observe.PopulateImageDigest(s, opts.AggregateOpts.Container, opts.AggregateOpts.Image, opts.RuntimeBin, opts.Fixture != "", stderr)
	ComputeDeviceConfidence(s)
	return s, nil
}

// deviceToSidecar assembles a *Sidecar from the device observation. The
// capability and fs scaffolding is left at NewSidecar's empty defaults; the
// device section (device_paths + device_recommendation) carries the
// observation. PLAN.md §Output schema: one observer per run populates its own
// block.
func deviceToSidecar(dev *DeviceObservation, opts attrib.Opts) *sidecar.Sidecar {
	s := sidecar.NewSidecar()
	s.Target.Mode = opts.ModeLabel()
	s.Target.Selector = opts.Selector()
	s.Target.ReplicasObserved = len(dev.PerReplica)
	for rid, c := range dev.PerReplicaCount {
		s.Target.PerReplicaEventCounts[rid] = c
	}
	if opts.Image != "" {
		s.Image = opts.Image
	} else {
		s.Image = dev.Image
	}

	ApplyDeviceFields(s, dev)

	s.TraceHealth.EventsRecorded = dev.EventCount
	s.TraceHealth.EventsDropped = dev.Dropped
	s.TraceHealth.Finalise()
	return s
}

// ApplyDeviceFields populates the device section of s (device_recommendation,
// device_paths, and replica_device_disagreement) from the device observation.
// It is shared by deviceToSidecar (the standalone --observe devices path) and
// the privileged-composition merge, which folds device fields into a sidecar
// that already carries the capability observation. It deliberately touches only
// the device-specific fields — not Target.Mode/Selector/Image or trace_health,
// which the two callers own differently — so the merge can add devices to a cap
// sidecar without clobbering the cap Target.
func ApplyDeviceFields(s *sidecar.Sidecar, dev *DeviceObservation) {
	rec := deviceToRecommendation(dev.Devices)
	s.DeviceRecommendation = &rec

	dp := make([]sidecar.DevicePath, 0, len(dev.Devices))
	for _, p := range dev.Devices {
		entry := sidecar.DevicePath{Path: p}
		if st := dev.Stats[p]; st != nil {
			entry.EventCount = st.eventCount
			entry.CommSamples = observe.SortedKeys(st.commSamples)
		}
		dp = append(dp, entry)
	}
	s.DevicePaths = dp

	// Cross-replica device-set disagreement under --all-matching: any union
	// device node not observed on every replica. The device analog of
	// ReplicaCapDisagreement / ReplicaWritePathDisagreement; undefined (left
	// empty) with <2 replicas. Feeds ComputeDeviceConfidence. A non-empty list
	// means the workload exercised replicas unevenly — the union recommendation
	// grants devices some replica never opened, which a reviewer should weigh.
	if len(dev.PerReplica) > 1 {
		perReplicaSets := make(map[string]map[string]struct{}, len(dev.PerReplica))
		for rid, devices := range dev.PerReplica {
			set := make(map[string]struct{}, len(devices))
			for _, d := range devices {
				set[d] = struct{}{}
			}
			perReplicaSets[rid] = set
		}
		var dis []string
		for _, d := range dev.Devices {
			for _, set := range perReplicaSets {
				if _, ok := set[d]; !ok {
					dis = append(dis, d)
					break
				}
			}
		}
		sort.Strings(dis)
		s.Target.ReplicaDeviceDisagreement = dis
	}
}

// ObserveDevices spawns `ig run trace_open --paths --output json` and aggregates
// non-default device opens for the lifetime of ctx. It is observeWrites with
// AggregateDevices swapped in for aggregateWrites — the same gadget (trace_open,
// --paths for the symlink-resolved fpath), the same stderr-drain + ringbuf-loss
// accounting; only the classifier differs (isDeviceOpen vs IsWrite/isRootfsWrite).
func ObserveDevices(ctx context.Context, igBin string, filterArgs []string, opts attrib.Opts, stderrSink io.Writer) (*DeviceObservation, error) {
	args := append(append([]string{}, filterArgs...), "--paths", "--output", "json")
	obs, lost, err := ig.RunGadget(ctx, igBin, ig.TraceOpenGadget, args, stderrSink,
		func(stdout io.Reader) (*DeviceObservation, error) { return AggregateDevices(stdout, opts) })
	if err != nil {
		return nil, err
	}
	if obs != nil {
		obs.Dropped = lost
	}
	return obs, nil
}
