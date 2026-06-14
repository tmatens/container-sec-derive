package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// privilegedPipelineOpts bundles every input the v0.3 privileged-mode
// decomposition observe pipeline takes. Unlike the single-observer paths it has
// TWO signal sources — trace_capabilities (the cap_add half) and trace_open
// filtered to /dev (the devices half) — so it carries two fixture inputs:
// Fixture (the trace_capabilities NDJSON, as for the cap observer) and
// DeviceFixture (the trace_open NDJSON, the device half). Either may be empty in
// fixture mode (an absent half contributes nothing). This mirrors how the fs
// observer added --mounts-fixture as a second hermetic input.
type privilegedPipelineOpts struct {
	AggregateOpts  aggregateOpts
	Fixture        string // trace_capabilities NDJSON (caps half)
	DeviceFixture  string // trace_open NDJSON (devices half)
	FixtureStderr  string
	InspectFixture string
	IGBin          string
	Duration       time.Duration
	Workload       string
}

// producePrivilegedObservation runs the capability and device observers
// together and synthesizes the minimum non-privileged equivalent. Live, the two
// gadgets run as concurrent ig subprocesses for one window; in fixture mode the
// two NDJSON inputs are aggregated independently. The cap observation is the
// base sidecar (it owns Capabilities, the cap Target, the entrypoint
// cross-check); the device fields are folded in via applyDeviceFields; and the
// privileged_decomposition block records the headline conclusion. trace_health
// sums both streams (combined ringbuf health), and confidence is the worse of
// the two observers' grades (computePrivilegedConfidence).
//
// security_opt is out of scope for v0.3 (no AppArmor/seccomp denial gadget at
// the pinned IG); the standing Caveat covers the residual that relaxed MAC,
// which csd does not yet observe, may still be load-bearing.
func producePrivilegedObservation(opts privilegedPipelineOpts, stderr io.Writer) (*Sidecar, error) {
	observedAt := time.Now().UTC()
	var (
		capS *Sidecar
		dev  *deviceObservation
		err  error
	)

	if opts.Fixture != "" || opts.DeviceFixture != "" {
		// Fixture mode: caps from Fixture, devices from DeviceFixture; either
		// half may be absent.
		if opts.Fixture != "" {
			src, openErr := os.Open(opts.Fixture)
			if openErr != nil {
				return nil, fmt.Errorf("open fixture: %w", openErr)
			}
			defer src.Close()
			if capS, err = aggregate(src, opts.AggregateOpts); err == nil && capS != nil && opts.FixtureStderr != "" {
				errSrc, openErrErr := os.Open(opts.FixtureStderr)
				if openErrErr != nil {
					return nil, fmt.Errorf("open fixture-stderr: %w", openErrErr)
				}
				capS.TraceHealth.EventsDropped = parseIGStderr(errSrc, nil)
				errSrc.Close()
			}
		}
		if err == nil && opts.DeviceFixture != "" {
			dsrc, openErr := os.Open(opts.DeviceFixture)
			if openErr != nil {
				return nil, fmt.Errorf("open device-fixture: %w", openErr)
			}
			defer dsrc.Close()
			dev, err = aggregateDevices(dsrc, opts.AggregateOpts)
		}
	} else {
		// Live mode: trace_capabilities + trace_open run concurrently for one
		// window, each its own ig subprocess.
		noteWSL2IfDetected(stderr)
		if verr := checkIGVersion(opts.IGBin, stderr); verr != nil {
			return nil, verr
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()

		var (
			wg             sync.WaitGroup
			capErr, devErr error
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			capS, capErr = observe(ctx, opts.IGBin, opts.AggregateOpts, stderr)
		}()
		go func() {
			defer wg.Done()
			dev, devErr = observeDevices(ctx, opts.IGBin, opts.AggregateOpts, stderr)
		}()
		wg.Wait()
		switch {
		case capErr != nil:
			err = capErr
		case devErr != nil:
			err = devErr
		}
		if capS != nil {
			capS.DurationSeconds = int(opts.Duration.Seconds())
		}
	}
	if err != nil {
		var amb *ambiguousSelectionError
		if errors.As(err, &amb) {
			return nil, wrapCoded(ExitTargetAmbiguous, err)
		}
		return nil, err
	}

	// Base sidecar = the cap observation (Capabilities + cap Target +
	// cross-check). An absent cap half (fixture mode, --fixture omitted) still
	// yields a well-formed empty cap sidecar.
	s := capS
	if s == nil {
		s = NewSidecar()
		s.Target.Mode = opts.AggregateOpts.modeLabel()
		s.Target.Selector = opts.AggregateOpts.selector()
	}

	if dev != nil {
		applyDeviceFields(s, dev)
		// Combined ringbuf health across both gadget streams.
		s.TraceHealth.EventsRecorded += dev.EventCount
		s.TraceHealth.EventsDropped += dev.Dropped
		if s.Image == "" {
			s.Image = dev.Image
		}
	}
	finaliseTraceHealth(&s.TraceHealth)

	devices := []string{}
	if s.DeviceRecommendation != nil {
		devices = s.DeviceRecommendation.Devices
	}
	s.PrivilegedDecomposition = &privilegedDecomposition{
		DropPrivileged: true,
		CapAdd:         s.CapNames(),
		Devices:        devices,
	}

	s.ObservedAt = observedAt
	s.Workload = opts.Workload
	applyEntrypointCrossCheck(s, opts.InspectFixture, opts.Fixture != "" || opts.DeviceFixture != "", stderr)
	computePrivilegedConfidence(s)
	return s, nil
}

// computePrivilegedConfidence grades a privileged-composition run as the WORSE
// of the capability and device observers' grades, with the union of their
// factors. Both halves must be trustworthy for the decomposition to be — a
// confident cap set paired with a sparse, unverified device observation is only
// as good as the device half, and vice versa. The two sub-rubrics each write
// s.Confidence, so this snapshots around them.
func computePrivilegedConfidence(s *Sidecar) {
	computeConfidence(s)
	capLevel := s.Confidence.Level
	capFactors := prefixFactors("caps", s.Confidence.Factors)

	computeDeviceConfidence(s)
	devLevel := s.Confidence.Level
	devFactors := prefixFactors("devices", s.Confidence.Factors)

	s.Confidence.Level = worseConfidence(capLevel, devLevel)
	s.Confidence.Factors = append(capFactors, devFactors...)
}

// prefixFactors tags each factor with which observer produced it, so a merged
// factor list stays traceable to its sub-rubric.
func prefixFactors(observer string, factors []string) []string {
	out := make([]string, len(factors))
	for i, f := range factors {
		out[i] = "[" + observer + "] " + f
	}
	return out
}

// confidenceRank orders the levels low < moderate < high for worseConfidence.
func confidenceRank(level string) int {
	switch level {
	case ConfidenceHigh:
		return 2
	case ConfidenceModerate:
		return 1
	default:
		return 0
	}
}

// worseConfidence returns the lower-confidence of two grades.
func worseConfidence(a, b string) string {
	if confidenceRank(a) <= confidenceRank(b) {
		return a
	}
	return b
}
