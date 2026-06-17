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

// devicePipelineOpts bundles every input the v0.3 device-decomposition observe
// pipeline takes, mirroring fsPipelineOpts. The device observer's single signal
// source is trace_open (filtered to non-default /dev nodes); unlike the fs
// observer it needs no mount config — a device grant is not volume-correlated —
// so there is no MountsFixture analog.
type devicePipelineOpts struct {
	AggregateOpts aggregateOpts
	Fixture       string // trace_open NDJSON; empty → live ig
	IGBin         string
	Duration      time.Duration
	Workload      string // --workload path recorded on the sidecar + fed to device confidence
}

// produceDeviceObservation runs the fixture-or-live device observe path
// end-to-end and returns a fully populated *Sidecar with the device
// recommendation, device_paths evidence, trace_health, and device confidence
// already scored. It is the device-observer analog of produceFSObservation:
// same fixture-vs-live branch shape and typed-exit translation. The device
// nodes come from trace_open; deviceToSidecar assembles the artifact.
func produceDeviceObservation(opts devicePipelineOpts, stderr io.Writer) (*Sidecar, error) {
	observedAt := time.Now().UTC()
	var (
		dev *deviceObservation
		err error
	)
	if opts.Fixture != "" {
		src, openErr := os.Open(opts.Fixture)
		if openErr != nil {
			return nil, fmt.Errorf("open fixture: %w", openErr)
		}
		defer src.Close()
		dev, err = aggregateDevices(src, opts.AggregateOpts)
	} else {
		noteWSL2IfDetected(stderr)
		if verr := checkIGVersion(opts.IGBin, stderr); verr != nil {
			return nil, verr
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()
		dev, err = observeDevices(ctx, opts.IGBin, opts.AggregateOpts, stderr)
	}
	if err != nil {
		var amb *ambiguousSelectionError
		if errors.As(err, &amb) {
			return nil, wrapCoded(ExitTargetAmbiguous, err)
		}
		return nil, err
	}

	s := deviceToSidecar(dev, opts.AggregateOpts)
	s.ObservedAt = observedAt
	s.Workload = opts.Workload
	if opts.Fixture == "" {
		s.DurationSeconds = int(opts.Duration.Seconds())
	}
	computeDeviceConfidence(s)
	return s, nil
}

// deviceToSidecar assembles a *Sidecar from the device observation. The
// capability and fs scaffolding is left at NewSidecar's empty defaults; the
// device section (device_paths + device_recommendation) carries the
// observation. PLAN.md §Output schema: one observer per run populates its own
// block.
func deviceToSidecar(dev *deviceObservation, opts aggregateOpts) *Sidecar {
	s := NewSidecar()
	s.Target.Mode = opts.modeLabel()
	s.Target.Selector = opts.selector()
	s.Target.ReplicasObserved = len(dev.PerReplica)
	for rid, c := range dev.PerReplicaCount {
		s.Target.PerReplicaEventCounts[rid] = c
	}
	if opts.Image != "" {
		s.Image = opts.Image
	} else {
		s.Image = dev.Image
	}

	applyDeviceFields(s, dev)

	s.TraceHealth.EventsRecorded = dev.EventCount
	s.TraceHealth.EventsDropped = dev.Dropped
	finaliseTraceHealth(&s.TraceHealth)
	return s
}

// applyDeviceFields populates the device section of s (device_recommendation,
// device_paths, and replica_device_disagreement) from the device observation.
// It is shared by deviceToSidecar (the standalone --observe devices path) and
// the privileged-composition merge, which folds device fields into a sidecar
// that already carries the capability observation. It deliberately touches only
// the device-specific fields — not Target.Mode/Selector/Image or trace_health,
// which the two callers own differently — so the merge can add devices to a cap
// sidecar without clobbering the cap Target.
func applyDeviceFields(s *Sidecar, dev *deviceObservation) {
	rec := deviceToRecommendation(dev.Devices)
	s.DeviceRecommendation = &rec

	dp := make([]DevicePath, 0, len(dev.Devices))
	for _, p := range dev.Devices {
		entry := DevicePath{Path: p}
		if st := dev.Stats[p]; st != nil {
			entry.EventCount = st.eventCount
			entry.CommSamples = sortedKeys(st.commSamples)
		}
		dp = append(dp, entry)
	}
	s.DevicePaths = dp

	// Cross-replica device-set disagreement under --all-matching: any union
	// device node not observed on every replica. The device analog of
	// ReplicaCapDisagreement / ReplicaWritePathDisagreement; undefined (left
	// empty) with <2 replicas. Feeds computeDeviceConfidence. A non-empty list
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

// observeDevices spawns `ig run trace_open --paths --output json` and aggregates
// non-default device opens for the lifetime of ctx. It is observeWrites with
// aggregateDevices swapped in for aggregateWrites — the same gadget (trace_open,
// --paths for the symlink-resolved fpath), the same stderr-drain + ringbuf-loss
// accounting; only the classifier differs (isDeviceOpen vs IsWrite/isRootfsWrite).
func observeDevices(ctx context.Context, igBin string, opts aggregateOpts, stderrSink io.Writer) (*deviceObservation, error) {
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

	var (
		wg   sync.WaitGroup
		lost int
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		lost = parseIGStderr(stderrPipe, stderrSink)
	}()

	obs, aggErr := aggregateDevices(stdout, opts)
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
