package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// updateGolden regenerates testdata/sidecar_golden.json from the current
// aggregator output. Run `go test ./... -update-golden` to refresh after
// an intentional schema change; never silently.
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/sidecar_golden.json from current output")

// TestSidecar_GoldenPostgres1 pins the canonical JSON shape against
// testdata/ig-versions/v0.51.0/sample.ndjson. PLAN.md §Output schema requires schema_version
// stability; this is the test that enforces it for v0.1.x. Every field
// rename, type change, or silent drop in a Capability sub-field has to
// surface here before it can merge.
func TestSidecar_GoldenPostgres1(t *testing.T) {
	f, err := os.Open("testdata/ig-versions/v0.51.0/sample.ndjson")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	s, err := aggregate(f, aggregateOpts{Container: "postgres-1", InitWindowMs: 500})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	// Fixed inputs so the JSON is reproducible across runs. Live `run()`
	// sets ObservedAt to time.Now() and DurationSeconds from --duration;
	// the golden is testing shape + aggregation math, not those.
	s.ObservedAt = time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	s.DurationSeconds = 600
	computeConfidence(s)

	got, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n') // match json.Encoder trailing newline

	goldenPath := filepath.Join("testdata", "sidecar_golden.json")
	if *updateGolden {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s (%d bytes)", goldenPath, len(got))
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update-golden to create)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch. Diff:\n--- want\n%s\n--- got\n%s", want, got)
	}
}

// TestFSSidecar_Golden pins the v0.2 fs observer's JSON shape — the additive
// writable_paths + fs_recommendation blocks alongside the empty capability
// scaffolding — against testdata/fs_sidecar_golden.json. Built from the
// committed trace_open fixture + the postgres mounts fixture; ObservedAt and
// DurationSeconds are fixed so the document is reproducible (same approach as
// TestSidecar_GoldenPostgres1). Run with -update-golden to refresh.
func TestFSSidecar_Golden(t *testing.T) {
	f, err := os.Open("testdata/ig-versions/v0.51.0/trace_open_sample.ndjson")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	writes, err := aggregateWrites(f, aggregateOpts{Container: "postgres-1"})
	if err != nil {
		t.Fatalf("aggregateWrites: %v", err)
	}
	mounts, err := loadMountsFixture("testdata/postgres/mounts.json")
	if err != nil {
		t.Fatalf("loadMountsFixture: %v", err)
	}
	s := fsToSidecar(writes, mounts, aggregateOpts{Container: "postgres-1"})
	s.ObservedAt = time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	s.DurationSeconds = 600
	computeFSConfidence(s)

	got, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "fs_sidecar_golden.json")
	if *updateGolden {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s (%d bytes)", goldenPath, len(got))
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update-golden to create)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("fs golden mismatch. Diff:\n--- want\n%s\n--- got\n%s", want, got)
	}
}

// TestRun_InspectFixturePopulatesCrossCheck exercises --inspect-fixture
// end-to-end through run(): flag parsing, applyEntrypointCrossCheck
// wiring, and emission into the sidecar file. Uses the postgres fixture
// + a divergent inspect fixture so both coverage_warnings and
// expected_caps_from_entrypoint end up non-empty.
func TestRun_InspectFixturePopulatesCrossCheck(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "sidecar.json")

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--inspect-fixture", "testdata/entrypoint/gosu_chown_divergent.json",
		"--container", "postgres-1",
		"--out", out,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, stderr.String())
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	var s Sidecar
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("parse sidecar: %v", err)
	}

	// Divergent fixture expects CHOWN/DAC_OVERRIDE/FOWNER (chown signal),
	// SETUID/SETGID (gosu signal), and NET_BIND_SERVICE (setcap history).
	// Observed in postgres-1 fixture: CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID.
	// Delta: NET_BIND_SERVICE -> exactly one warning.
	wantExpected := []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "NET_BIND_SERVICE", "SETGID", "SETUID"}
	if !equalSlice(s.ExpectedCapsFromEntrypoint, wantExpected) {
		t.Errorf("expected_caps_from_entrypoint = %v, want %v",
			s.ExpectedCapsFromEntrypoint, wantExpected)
	}
	if len(s.CoverageWarnings) != 1 {
		t.Fatalf("want 1 coverage warning (NET_BIND_SERVICE), got %d:\n%v",
			len(s.CoverageWarnings), s.CoverageWarnings)
	}
	if !strings.Contains(s.CoverageWarnings[0], "NET_BIND_SERVICE") {
		t.Errorf("warning should name NET_BIND_SERVICE: %q", s.CoverageWarnings[0])
	}

	// Phase B (Step 32): warnings non-empty forces low. Asserts both the
	// factor text and the resulting grade.
	joined := strings.Join(s.Confidence.Factors, "\n")
	if !strings.Contains(joined, "low: 1 entrypoint coverage warnings present") {
		t.Errorf("factors should include coverage-warnings low:\n%s", joined)
	}
	if s.Confidence.Level != ConfidenceLow {
		t.Errorf("warnings should force low; got %q", s.Confidence.Level)
	}

	// Warnings should also have been echoed to stderr during the run.
	if !strings.Contains(stderr.String(), "coverage_warning") {
		t.Errorf("stderr should surface coverage_warning prose:\n%s", stderr.String())
	}
}

// TestRun_InspectFixtureCleanCrossCheck covers the postgres argv-only
// fixture where zero static signals fire -- the "ran but no signals"
// factor path, distinct from both clean-with-signals and skipped.
func TestRun_InspectFixtureCleanCrossCheck(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "sidecar.json")

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--inspect-fixture", "testdata/entrypoint/postgres_argv_only.json",
		"--container", "postgres-1",
		"--out", out,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, stderr.String())
	}

	data, _ := os.ReadFile(out)
	var s Sidecar
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("parse sidecar: %v", err)
	}
	if len(s.ExpectedCapsFromEntrypoint) != 0 {
		t.Errorf("argv-only postgres should produce no expected caps, got %v",
			s.ExpectedCapsFromEntrypoint)
	}
	if len(s.CoverageWarnings) != 0 {
		t.Errorf("no expected caps implies no warnings, got %v", s.CoverageWarnings)
	}
	joined := strings.Join(s.Confidence.Factors, "\n")
	if !strings.Contains(joined, "entrypoint cross-check ran; no static signals matched") {
		t.Errorf("factors should include no-signals-matched:\n%s", joined)
	}
}

// TestRun_OutFlagWritesSidecar exercises the --out plumbing end-to-end:
// flag parsing, aggregate path, serialization, and file-on-disk shape.
// Golden-diffing is TestSidecar_GoldenPostgres1's job; this test only
// asserts the file exists and round-trips cleanly.
func TestRun_OutFlagWritesSidecar(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "sidecar.json")

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--out", out,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, stderr.String())
	}
	// Stdout compose stanza is unaffected by --out: machines read the
	// sidecar JSON, humans paste the compose block, they don't compete.
	wantStdout := "cap_drop:\n  - ALL\ncap_add:\n  - CHOWN\n  - DAC_OVERRIDE\n  - FOWNER\n  - SETGID\n  - SETUID\n"
	if stdout.String() != wantStdout {
		t.Errorf("stdout changed under --out:\ngot:\n%s\nwant:\n%s", stdout.String(), wantStdout)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	var s Sidecar
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("sidecar is not valid JSON: %v", err)
	}
	if s.SchemaVersion != "1.1" {
		t.Errorf("SchemaVersion = %q, want %q", s.SchemaVersion, "1.1")
	}
	if len(s.Capabilities) != 5 {
		t.Errorf("got %d capabilities, want 5", len(s.Capabilities))
	}
	if s.ObservedAt.IsZero() {
		t.Error("ObservedAt must be set for live run (even fixture mode); got zero time")
	}
	if s.Image != "postgres:16" {
		t.Errorf("Image = %q, want %q", s.Image, "postgres:16")
	}
}
