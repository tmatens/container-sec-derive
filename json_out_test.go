package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestWriteJSON_RoundTripsSidecar(t *testing.T) {
	s := sidecar.NewSidecar()
	s.Image = "postgres:16"
	s.Capabilities = []sidecar.Capability{
		{Name: "CHOWN", EventCount: 3},
		{Name: "SETUID", EventCount: 1},
	}
	var buf bytes.Buffer
	if err := writeJSON(&buf, s); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	var round sidecar.Sidecar
	if err := json.Unmarshal(buf.Bytes(), &round); err != nil {
		t.Fatalf("round-trip decode: %v\n%s", err, buf.String())
	}
	if round.Image != "postgres:16" {
		t.Errorf("Image = %q, want postgres:16", round.Image)
	}
	if len(round.Capabilities) != 2 || round.Capabilities[0].Name != "CHOWN" {
		t.Errorf("capabilities lost shape after round-trip: %+v", round.Capabilities)
	}
}

func TestWriteJSON_MatchesWriteSidecarByteForByte(t *testing.T) {
	// Stdout (--format json) and --out MUST produce identical bytes.
	// Downstream tooling that pipes stdout into jq and reads --out from
	// disk should never observe a shape divergence.
	f, err := os.Open("testdata/ig-versions/v0.51.0/sample.ndjson")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	s, err := aggregate(f, attrib.Opts{Container: "postgres-1", InitWindowMs: 500})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	computeConfidence(s)

	var stdoutBuf bytes.Buffer
	if err := writeJSON(&stdoutBuf, s); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), "sidecar.json")
	if err := writeSidecar(s, outPath); err != nil {
		t.Fatalf("writeSidecar: %v", err)
	}
	onDisk, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if !bytes.Equal(stdoutBuf.Bytes(), onDisk) {
		t.Errorf("stdout vs --out byte divergence:\n--- stdout\n%s\n--- --out\n%s", stdoutBuf.Bytes(), onDisk)
	}
}

func TestRun_FormatJSONEmitsSidecarToStdout(t *testing.T) {
	// End-to-end: --format json routes the canonical sidecar to stdout.
	// Asserts the dispatch wiring, not the schema (golden test owns that).
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "json",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, stderr.String())
	}
	var s sidecar.Sidecar
	if err := json.Unmarshal(stdout.Bytes(), &s); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if s.SchemaVersion != sidecar.SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", s.SchemaVersion, sidecar.SchemaVersion)
	}
	if len(s.Capabilities) != 5 {
		t.Errorf("got %d capabilities, want 5", len(s.Capabilities))
	}
	if !strings.HasSuffix(stdout.String(), "}\n") {
		t.Errorf("json output should end with newline-terminated object, got tail: %q", stdout.String()[max(0, len(stdout.String())-10):])
	}
}

func TestRun_FormatJSONAndOutAgree(t *testing.T) {
	// `--format json` stdout and `--out` file share the same encoder path,
	// so end-to-end they must remain byte-identical. This catches any
	// future regression that reintroduces two separate write paths.
	dir := t.TempDir()
	outPath := filepath.Join(dir, "sidecar.json")

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "json",
		"--out", outPath,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, stderr.String())
	}
	onDisk, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if !bytes.Equal(stdout.Bytes(), onDisk) {
		t.Errorf("--format json stdout differs from --out file:\n--- stdout\n%s\n--- --out\n%s", stdout.Bytes(), onDisk)
	}
}
