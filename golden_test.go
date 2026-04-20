package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// updateGolden regenerates testdata/sidecar_golden.json from the current
// aggregator output. Run `go test ./... -update-golden` to refresh after
// an intentional schema change; never silently.
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/sidecar_golden.json from current output")

// TestSidecar_GoldenPostgres1 pins the canonical JSON shape against
// testdata/sample.ndjson. PLAN.md §Output schema requires schema_version
// stability; this is the test that enforces it for v0.1.x. Every field
// rename, type change, or silent drop in a Capability sub-field has to
// surface here before it can merge.
func TestSidecar_GoldenPostgres1(t *testing.T) {
	f, err := os.Open("testdata/sample.ndjson")
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

// TestRun_OutFlagWritesSidecar exercises the --out plumbing end-to-end:
// flag parsing, aggregate path, serialization, and file-on-disk shape.
// Golden-diffing is TestSidecar_GoldenPostgres1's job; this test only
// asserts the file exists and round-trips cleanly.
func TestRun_OutFlagWritesSidecar(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "sidecar.json")

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/sample.ndjson",
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
	if s.SchemaVersion != "1.0" {
		t.Errorf("SchemaVersion = %q, want %q", s.SchemaVersion, "1.0")
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
