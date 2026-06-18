package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// runVerify is the entry point for `csd verify`. Two input shapes:
//
//   - **Sidecar-vs-sidecar (Step 22).** `--baseline <sidecar> --observation
//     <sidecar>` reads two prior `csd observe` sidecars and classifies
//     the pair. The user runs observe twice (once for the baseline,
//     once under the proposed config) and feeds both in.
//   - **Run-mode (Step 23).** `--baseline <sidecar>` plus the standard
//     observe-mode flags (`--container`/`--image`/`--all-matching`/
//     `--fixture`/`--workload`/`--duration`/`--init-window-ms`/`--ig`/
//     `--inspect-fixture`/`--fixture-stderr`) runs an internal
//     observation against the user-supplied target (which they have
//     already restarted under the proposed config) and classifies it
//     against the baseline. Saves the user from running observe a
//     second time and capturing the sidecar by hand.
//
// Container-spawning under proposed config (PLAN.md §Verify runtime
// context's compose-anchored fresh container) is v1 scope; v0.1-rc lands
// the classifier plus a one-shot wrapper, and the user-supplied
// container/image is what actually carries the proposed config.
func runVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("csd verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		baseline    = fs.String("baseline", "", "path to the baseline observe-mode evidence sidecar (the proposed profile under verify)")
		observation = fs.String("observation", "", "path to the verify-time observe-mode evidence sidecar (events captured under the proposed config); mutually exclusive with the observe-mode flags")
		// Observe-mode flags. Mirror run()'s defaults so existing user
		// muscle memory (--init-window-ms 500, --duration 30s) carries
		// over verbatim. --format / --out / --compose-in / --service /
		// --allow-exploratory are deliberately NOT exposed: verify's
		// stdout is verify_result JSON, not a formatter artifact.
		container      = fs.String("container", "", "run-mode: target container id or name (mutually exclusive with --image)")
		image          = fs.String("image", "", "run-mode: select containers by image reference")
		allMatching    = fs.Bool("all-matching", false, "run-mode: aggregate across all replicas matching --image")
		fixture        = fs.String("fixture", "", "run-mode: read ig-format NDJSON from this file instead of spawning ig")
		fixtureErr     = fs.String("fixture-stderr", "", "run-mode + fixture-mode: file of ig stderr lines; drops parsed as if piped from live ig")
		inspectFixture = fs.String("inspect-fixture", "", "run-mode: pre-captured image-inspection JSON")
		duration       = fs.Duration("duration", 30*time.Second, "run-mode: observation window (ignored in --fixture mode)")
		igBin          = fs.String("ig", "ig", "run-mode: path to the ig binary")
		initWindowMs   = fs.Int("init-window-ms", 500, "run-mode: drop capability events observed within this many ms of the first matching event (0 disables)")
		workload       = fs.String("workload", "", "run-mode: path to the workload script that exercised the container under the proposed config")
	)
	if err := fs.Parse(args); err != nil {
		return exit.WrapCoded(exit.Usage, err)
	}
	if *baseline == "" {
		return exit.CodedErrorf(exit.Usage, "csd verify requires --baseline <sidecar>")
	}

	// Mode selection: --observation picks sidecar-vs-sidecar; presence
	// of any observe-mode selector picks run-mode. Mixing the two is a
	// usage error -- the user is asking for two different things.
	hasRunModeSelector := *container != "" || *image != "" || *fixture != ""
	if *observation == "" && !hasRunModeSelector {
		return exit.CodedErrorf(exit.Usage,
			"csd verify needs either --observation <sidecar> (sidecar-vs-sidecar) or one of --container/--image/--fixture (run-mode)")
	}
	if *observation != "" && hasRunModeSelector {
		return exit.CodedErrorf(exit.Usage,
			"--observation is mutually exclusive with --container/--image/--fixture; sidecar-vs-sidecar mode reads a pre-existing sidecar, run-mode produces one internally")
	}
	if *allMatching && *image == "" {
		return exit.CodedErrorf(exit.Usage, "--all-matching requires --image")
	}
	if *container != "" && *image != "" {
		return exit.CodedErrorf(exit.Usage, "--container and --image are mutually exclusive")
	}
	if *workload != "" {
		if _, err := os.Stat(*workload); err != nil {
			return exit.WrapCoded(exit.Usage, fmt.Errorf("--workload %q: %w", *workload, err))
		}
	}

	baseSidecar, err := loadSidecar(*baseline)
	if err != nil {
		return exit.WrapCoded(exit.Usage, fmt.Errorf("--baseline: %w", err))
	}

	var obsSidecar *sidecar.Sidecar
	if *observation != "" {
		obsSidecar, err = loadSidecar(*observation)
		if err != nil {
			return exit.WrapCoded(exit.Usage, fmt.Errorf("--observation: %w", err))
		}
	} else {
		// Run-mode: produce the verify-time observation from the
		// user-supplied target. The target carries the proposed config
		// (the user restarted it before invoking verify); we just
		// observe it under the same workload.
		obsSidecar, err = produceObservation(observePipelineOpts{
			AggregateOpts: attrib.Opts{
				Container:    *container,
				Image:        *image,
				AllMatching:  *allMatching,
				InitWindowMs: *initWindowMs,
			},
			Fixture:        *fixture,
			FixtureStderr:  *fixtureErr,
			InspectFixture: *inspectFixture,
			IGBin:          *igBin,
			Duration:       *duration,
			Workload:       *workload,
		}, stderr)
		if err != nil {
			return err
		}
	}

	vr, code := classifyVerify(baseSidecar.CapNames(), obsSidecar, *baseline)
	if err := writeVerifyResult(stdout, vr); err != nil {
		return fmt.Errorf("write verify result: %w", err)
	}
	if code != exit.OK {
		// The verify result is the artifact even on nonzero exit; the
		// code is what tells CI that the proposed profile failed (10)
		// or trimming is possible (11). Wrap a short message so stderr
		// names the outcome without the user having to grep stdout.
		return exit.CodedErrorf(code, "csd verify outcome: %s", vr.Outcome)
	}
	return nil
}

// PLAN.md §Verify semantics defines three outcomes; values match the
// JSON tokens emitted in the verify_result schema.
const (
	VerifyOutcomeConsistent       = "consistent"
	VerifyOutcomeInsufficient     = "insufficient"
	VerifyOutcomeOverPermissioned = "over_permissioned"

	// VerifyCaveat is hard-coded so downstream consumers cannot strip
	// the "validates self-consistency, not general sufficiency" framing.
	// PLAN.md §Verify semantics paragraph 3 calls this out explicitly:
	// the field "exists precisely so downstream consumers (CI pipelines,
	// compose-lint contribution flow, humans skimming) cannot accidentally
	// promote 'verify passed' to 'profile is correct.'"
	VerifyCaveat = "Validates self-consistency under the recorded workload only. Paths not exercised by the workload are untested."
)

// VerifyResult is the canonical verify artifact, emitted to stdout (and
// optionally to --out for the same byte stream). PLAN.md §Verify
// semantics defines the schema; we keep the layout 1:1 even when fields
// are empty so consumers can rely on the shape.
//
// new_denials carries the cap-level data the observation sidecar already
// has -- comm samples, first-seen offset, and event count. PLAN.md's
// example shows pid/syscall fields, but those live on the raw event
// stream rather than the sidecar, so v0.1 emits the reduced-form fields
// instead. Step 23's run-mode could enrich this in a schema-additive
// bump if a real consumer surfaces a need.
type VerifyResult struct {
	VerifyOf        string         `json:"verify_of"`
	ImageDigest     string         `json:"image_digest,omitempty"`
	Workload        string         `json:"workload,omitempty"`
	DurationSeconds int            `json:"duration_seconds"`
	Outcome         string         `json:"outcome"`
	NewDenials      []VerifyDenial `json:"new_denials"`
	UnusedCaps      []string       `json:"unused_caps"`
	Caveat          string         `json:"caveat"`
}

// VerifyDenial is one cap that fired during the verify-time observation
// but was absent from the baseline profile. Sidecar-vs-sidecar mode does
// not retain per-event context (pid, syscall) -- those would require
// keeping the raw NDJSON or growing the sidecar shape, neither of which
// is justified for the v0.1 self-consistency check. CommSamples and
// FirstSeenOffsetMs come straight off the observation sidecar's
// Capability entry.
type VerifyDenial struct {
	Cap               string   `json:"cap"`
	CommSamples       []string `json:"comm_samples"`
	FirstSeenOffsetMs int64    `json:"first_seen_offset_ms"`
	EventCount        int      `json:"event_count"`
}

// classifyVerify is the pure function at the heart of `csd verify`.
// baselineCaps is the proposed profile (from the prior `csd observe`
// run); observation is the sidecar from the verify-time run under that
// profile. verifyOfPath is the user-supplied baseline path used for the
// verify_of field; observation supplies image/workload/duration.
//
// Outcome priority is insufficient > over_permissioned > consistent:
// if any verify-time cap fired that the baseline didn't list, that's
// the most actionable signal and takes precedence over unused caps.
// Returns *VerifyResult and the corresponding exit code.
func classifyVerify(baselineCaps []string, observation *sidecar.Sidecar, verifyOfPath string) (*VerifyResult, int) {
	baselineSet := map[string]struct{}{}
	for _, c := range baselineCaps {
		baselineSet[c] = struct{}{}
	}
	observedSet := map[string]struct{}{}
	for _, c := range observation.Capabilities {
		observedSet[c.Name] = struct{}{}
	}

	newDenials := []VerifyDenial{}
	for _, c := range observation.Capabilities {
		if _, ok := baselineSet[c.Name]; ok {
			continue
		}
		// CommSamples is already sorted by aggregate(); copy so the
		// verify result doesn't share backing storage with the input.
		samples := append([]string{}, c.CommSamples...)
		newDenials = append(newDenials, VerifyDenial{
			Cap:               c.Name,
			CommSamples:       samples,
			FirstSeenOffsetMs: c.FirstSeenOffsetMs,
			EventCount:        c.EventCount,
		})
	}

	unused := []string{}
	for _, c := range baselineCaps {
		if _, ok := observedSet[c]; !ok {
			unused = append(unused, c)
		}
	}

	vr := &VerifyResult{
		VerifyOf:        verifyOfPath,
		ImageDigest:     observation.ImageDigest,
		Workload:        observation.Workload,
		DurationSeconds: observation.DurationSeconds,
		NewDenials:      newDenials,
		UnusedCaps:      unused,
		Caveat:          VerifyCaveat,
	}
	switch {
	case len(newDenials) > 0:
		vr.Outcome = VerifyOutcomeInsufficient
		return vr, exit.VerifyInsufficient
	case len(unused) > 0:
		vr.Outcome = VerifyOutcomeOverPermissioned
		return vr, exit.VerifyOverPermissioned
	default:
		vr.Outcome = VerifyOutcomeConsistent
		return vr, exit.OK
	}
}

// loadSidecar reads and decodes a JSON evidence sidecar from path. The
// schema_version major must match the binary's view of the canonical
// schema (PLAN.md §Output schema "Schema evolution policy"); a different
// major is rejected up front rather than parsed leniently.
func loadSidecar(path string) (*sidecar.Sidecar, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s sidecar.Sidecar
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if s.SchemaVersion == "" {
		return nil, fmt.Errorf("%s: schema_version missing; not a csd sidecar", path)
	}
	// Within-1.x is accepted; cross-major is rejected. Cheap string
	// compare on the leading "1." rather than dragging in semver.
	if len(s.SchemaVersion) < 2 || s.SchemaVersion[0:2] != "1." {
		return nil, fmt.Errorf("%s: unsupported schema_version %q (binary speaks 1.x only)", path, s.SchemaVersion)
	}
	return &s, nil
}

// writeVerifyResult emits vr as indented JSON. Routes through json.Marshal
// rather than json.Encoder so the trailing newline matches writeJSON's
// shape -- consumers comparing verify output across runs see a stable
// byte stream.
func writeVerifyResult(w io.Writer, vr *VerifyResult) error {
	b, err := json.MarshalIndent(vr, "", "  ")
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	_, err = w.Write([]byte{'\n'})
	return err
}
