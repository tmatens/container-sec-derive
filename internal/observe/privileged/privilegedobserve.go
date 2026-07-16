package privileged

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

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/ig"
	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/observe/caps"
	"github.com/tmatens/container-sec-derive/internal/observe/devices"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// PrivilegedPipelineOpts bundles every input the v0.3 privileged-mode
// decomposition observe pipeline takes. Unlike the single-observer paths it has
// TWO signal sources — trace_capabilities (the cap_add half) and trace_open
// filtered to /dev (the devices half) — so it carries two fixture inputs:
// Fixture (the trace_capabilities NDJSON, as for the cap observer) and
// DeviceFixture (the trace_open NDJSON, the device half). Either may be empty in
// fixture mode (an absent half contributes nothing). This mirrors how the fs
// observer added --mounts-fixture as a second hermetic input.
type PrivilegedPipelineOpts struct {
	AggregateOpts  attrib.Opts
	Fixture        string // trace_capabilities NDJSON (caps half)
	DeviceFixture  string // trace_open NDJSON (devices half)
	FixtureStderr  string
	InspectFixture string
	IGBin          string
	RuntimeBin     string // container CLI for inspect/history (internal/runtime); empty → docker
	Duration       time.Duration
	Workload       string
	// GadgetFilter pushes an in-gadget --containername filter for a
	// --container target (see observe.GadgetContainerFilter). Opt-in: on
	// some runtime/ig combinations the filter matches nothing and the run
	// observes zero events.
	GadgetFilter bool
}

// ProducePrivilegedObservation runs the capability and device observers
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
// the pinned IG), so the decomposition is flagged Partial and carries
// PrivilegedSecurityOptCaveat. That gap is surfaced explicitly — in the JSON
// block, in every text formatter header (privilegedCaveatComment), and via the
// stderr advisory in emitAdvisoryWarnings — so a user cannot read the headline
// "drop privileged: true" without also seeing that the relaxed-MAC dimension is
// unobserved and may still be load-bearing.
func ProducePrivilegedObservation(opts PrivilegedPipelineOpts, stderr io.Writer) (*sidecar.Sidecar, error) {
	observedAt := time.Now().UTC()
	var (
		capS *sidecar.Sidecar
		dev  *devices.DeviceObservation
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
			if capS, err = caps.Aggregate(src, opts.AggregateOpts); err == nil && capS != nil && opts.FixtureStderr != "" {
				errSrc, openErrErr := os.Open(opts.FixtureStderr)
				if openErrErr != nil {
					return nil, fmt.Errorf("open fixture-stderr: %w", openErrErr)
				}
				capS.TraceHealth.EventsDropped = ig.ParseIGStderr(errSrc, nil)
				errSrc.Close()
			}
		}
		if err == nil && opts.DeviceFixture != "" {
			dsrc, openErr := os.Open(opts.DeviceFixture)
			if openErr != nil {
				return nil, fmt.Errorf("open device-fixture: %w", openErr)
			}
			defer dsrc.Close()
			dev, err = devices.AggregateDevices(dsrc, opts.AggregateOpts)
		}
	} else {
		// Live mode: trace_capabilities + trace_open run concurrently for one
		// window, each its own ig subprocess.
		observe.NoteWSL2IfDetected(stderr)
		if verr := ig.CheckIGVersion(opts.IGBin, stderr); verr != nil {
			return nil, verr
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeoutCancel := context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()

		// Resolved once and shared: both gadgets filter to the same target.
		var filter []string
		if opts.GadgetFilter {
			filter = observe.GadgetContainerFilter(opts.AggregateOpts.Container, opts.RuntimeBin, opts.IGBin, stderr)
		}
		var (
			wg             sync.WaitGroup
			capErr, devErr error
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			capS, capErr = caps.Observe(ctx, opts.IGBin, filter, opts.AggregateOpts, stderr)
		}()
		go func() {
			defer wg.Done()
			dev, devErr = devices.ObserveDevices(ctx, opts.IGBin, filter, opts.AggregateOpts, stderr)
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
		var amb *exit.AmbiguousSelectionError
		if errors.As(err, &amb) {
			return nil, exit.WrapCoded(exit.TargetAmbiguous, err)
		}
		return nil, err
	}

	// Base sidecar = the cap observation (Capabilities + cap Target +
	// cross-check). An absent cap half (fixture mode, --fixture omitted) still
	// yields a well-formed empty cap sidecar.
	s := capS
	if s == nil {
		s = sidecar.NewSidecar()
		s.Target.Mode = opts.AggregateOpts.ModeLabel()
		s.Target.Selector = opts.AggregateOpts.Selector()
	}

	if dev != nil {
		devices.ApplyDeviceFields(s, dev)
		// Combined ringbuf health across both gadget streams.
		s.TraceHealth.EventsRecorded += dev.EventCount
		s.TraceHealth.EventsDropped += dev.Dropped
		if s.Image == "" {
			s.Image = dev.Image
		}
	}
	s.TraceHealth.Finalise()

	devNodes := []string{}
	if s.DeviceRecommendation != nil {
		devNodes = s.DeviceRecommendation.Devices
	}
	s.PrivilegedDecomposition = &sidecar.PrivilegedDecomposition{
		DropPrivileged: true,
		CapAdd:         s.CapNames(),
		Devices:        devNodes,
		Partial:        true,
		SecurityOpt:    sidecar.PrivilegedSecurityOptCaveat,
	}

	s.ObservedAt = observedAt
	s.Workload = opts.Workload
	caps.ApplyEntrypointCrossCheck(s, opts.InspectFixture, opts.RuntimeBin, opts.Fixture != "" || opts.DeviceFixture != "", stderr)
	// Live digest fallback (see caps.ProduceObservation): robustly pin via the
	// container's image ID when the cross-check couldn't. No-op if already set.
	observe.PopulateImageDigest(s, opts.AggregateOpts.Container, opts.AggregateOpts.Image, opts.RuntimeBin, opts.Fixture != "" || opts.DeviceFixture != "", stderr)
	computePrivilegedConfidence(s)
	return s, nil
}

// computePrivilegedConfidence grades a privileged-composition run as the WORSE
// of the capability and device observers' grades, with the union of their
// factors. Both halves must be trustworthy for the decomposition to be — a
// confident cap set paired with a sparse, unverified device observation is only
// as good as the device half, and vice versa. The two sub-rubrics each write
// s.Confidence, so this snapshots around them.
func computePrivilegedConfidence(s *sidecar.Sidecar) {
	caps.ComputeConfidence(s)
	capLevel := s.Confidence.Level
	capFactors := observe.PrefixFactors("caps", s.Confidence.Factors)

	devices.ComputeDeviceConfidence(s)
	devLevel := s.Confidence.Level
	devFactors := observe.PrefixFactors("devices", s.Confidence.Factors)

	s.Confidence.Level = observe.WorseConfidence(capLevel, devLevel)
	s.Confidence.Factors = append(capFactors, devFactors...)
}
