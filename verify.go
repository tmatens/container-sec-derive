package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

// runVerify is the entry point for `csd verify`. v0.1-rc Step 22 ships
// the sidecar-vs-sidecar form: the user runs `csd observe` once to
// produce the baseline profile, applies the proposed config to the
// container themselves, runs `csd observe` a second time to produce
// the verify-time observation, and feeds both sidecars in. Step 23
// adds the run-mode that wraps observe to produce the second sidecar
// internally; until that lands, this subcommand strictly classifies
// pre-existing sidecars and does not touch the container runtime.
func runVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("csd verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		baseline    = fs.String("baseline", "", "path to the baseline observe-mode evidence sidecar (the proposed profile under verify)")
		observation = fs.String("observation", "", "path to the verify-time observe-mode evidence sidecar (events captured under the proposed config)")
	)
	if err := fs.Parse(args); err != nil {
		return wrapCoded(ExitUsage, err)
	}
	if *baseline == "" || *observation == "" {
		return codedErrorf(ExitUsage, "csd verify requires --baseline <sidecar> and --observation <sidecar>")
	}

	baseSidecar, err := loadSidecar(*baseline)
	if err != nil {
		return wrapCoded(ExitUsage, fmt.Errorf("--baseline: %w", err))
	}
	obsSidecar, err := loadSidecar(*observation)
	if err != nil {
		return wrapCoded(ExitUsage, fmt.Errorf("--observation: %w", err))
	}

	vr, code := classifyVerify(baseSidecar.CapNames(), obsSidecar, *baseline)
	if err := writeVerifyResult(stdout, vr); err != nil {
		return fmt.Errorf("write verify result: %w", err)
	}
	if code != ExitOK {
		// The verify result is the artifact even on nonzero exit; the
		// code is what tells CI that the proposed profile failed (10)
		// or trimming is possible (11). Wrap a short message so stderr
		// names the outcome without the user having to grep stdout.
		return codedErrorf(code, "csd verify outcome: %s", vr.Outcome)
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
func classifyVerify(baselineCaps []string, observation *Sidecar, verifyOfPath string) (*VerifyResult, int) {
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
		return vr, ExitVerifyInsufficient
	case len(unused) > 0:
		vr.Outcome = VerifyOutcomeOverPermissioned
		return vr, ExitVerifyOverPermissioned
	default:
		vr.Outcome = VerifyOutcomeConsistent
		return vr, ExitOK
	}
}

// loadSidecar reads and decodes a JSON evidence sidecar from path. The
// schema_version major must match the binary's view of the canonical
// schema (PLAN.md §Output schema "Schema evolution policy"); a different
// major is rejected up front rather than parsed leniently.
func loadSidecar(path string) (*Sidecar, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s Sidecar
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
