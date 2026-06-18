package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestParseMountDestinations(t *testing.T) {
	in := []byte(`[
	  {"Type":"volume","Destination":"/var/log","Source":"x"},
	  {"Type":"bind","Destination":"/data","Source":"y"},
	  {"Type":"tmpfs","Destination":""},
	  {"Type":"volume","Destination":"/data"}
	]`)
	got, err := parseMountDestinations(in)
	if err != nil {
		t.Fatal(err)
	}
	// Sorted, de-duplicated, empty Destination dropped.
	want := []string{"/data", "/var/log"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dest[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseMountDestinationsNull(t *testing.T) {
	// `docker inspect --format '{{json .Mounts}}'` prints `null` for a
	// container with no mounts; that is the empty set, not an error.
	for _, in := range []string{"null", "  null\n", "[]", ""} {
		got, err := parseMountDestinations([]byte(in))
		if err != nil {
			t.Errorf("input %q: unexpected error %v", in, err)
		}
		if len(got) != 0 {
			t.Errorf("input %q: got %v, want empty", in, got)
		}
	}
}

func TestParseMountDestinationsMalformed(t *testing.T) {
	if _, err := parseMountDestinations([]byte(`{not json`)); err == nil {
		t.Error("expected parse error on malformed input")
	}
}

func TestLoadMountsFixture(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mounts.json")
	if err := os.WriteFile(p, []byte(`[{"Destination":"/srv"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadMountsFixture(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "/srv" {
		t.Errorf("got %v, want [/srv]", got)
	}
	if _, err := loadMountsFixture(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected error for missing fixture file")
	}
}

// TestProduceFSObservationFixture exercises the fixture path end-to-end: the
// committed postgres trace_open fixture + a mounts fixture covering the data
// volume must yield read_only:true, the data write volume-covered, and the
// log/run-dir writes as tmpfs candidates.
func TestProduceFSObservationFixture(t *testing.T) {
	s, err := produceFSObservation(fsPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "postgres-1"},
		Fixture:       "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		MountsFixture: "testdata/postgres/mounts.json",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := s.FSRecommendation
	if rec == nil || !rec.ReadOnly {
		t.Fatalf("FSRecommendation = %+v, want ReadOnly=true", rec)
	}
	wantTmpfs := []string{"/var/log/postgresql", "/var/run/postgresql"}
	if strings.Join(rec.TmpfsPaths, ",") != strings.Join(wantTmpfs, ",") {
		t.Errorf("TmpfsPaths = %v, want %v", rec.TmpfsPaths, wantTmpfs)
	}
	wantCovered := []string{"/var/lib/postgresql/data/base/1/1259"}
	if strings.Join(rec.VolumeCovered, ",") != strings.Join(wantCovered, ",") {
		t.Errorf("VolumeCovered = %v, want %v", rec.VolumeCovered, wantCovered)
	}

	// writable_paths carries every observed write with its disposition.
	dispByPath := map[string]string{}
	for _, wp := range s.WritablePaths {
		dispByPath[wp.Path] = wp.Disposition
	}
	if dispByPath["/var/lib/postgresql/data/base/1/1259"] != sidecar.DispositionVolumeCovered {
		t.Errorf("data write disposition = %q, want volume_covered", dispByPath["/var/lib/postgresql/data/base/1/1259"])
	}
	if dispByPath["/var/log/postgresql/postgresql.log"] != sidecar.DispositionTmpfsCandidate {
		t.Errorf("log write disposition = %q, want tmpfs_candidate", dispByPath["/var/log/postgresql/postgresql.log"])
	}
	if got := len(s.WritablePaths); got != 3 {
		t.Errorf("writable_paths len = %d, want 3", got)
	}
	// trace_health: 3 write events recorded, none dropped, in fixture mode.
	if s.TraceHealth.EventsRecorded != 3 || s.TraceHealth.DropRate != 0 {
		t.Errorf("trace_health = %+v, want 3 recorded / 0 drop", s.TraceHealth)
	}
	// The capability scaffolding stays empty on an fs run.
	if len(s.Capabilities) != 0 {
		t.Errorf("Capabilities = %v, want empty on an fs run", s.Capabilities)
	}
	// Confidence is scored (3 events < 100 + no workload → low).
	if s.Confidence.Level != sidecar.ConfidenceLow {
		t.Errorf("confidence = %q, want low (sparse + no workload)", s.Confidence.Level)
	}
}

// TestProduceFSObservationNoMountsFixture: hermetic fixture mode with no
// --mounts-fixture has no mount config, so every write becomes a tmpfs
// candidate (the data write is no longer volume-covered).
func TestProduceFSObservationNoMountsFixture(t *testing.T) {
	s, err := produceFSObservation(fsPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "postgres-1"},
		Fixture:       "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := s.FSRecommendation
	if len(rec.VolumeCovered) != 0 {
		t.Errorf("VolumeCovered = %v, want empty (no mounts supplied)", rec.VolumeCovered)
	}
	want := []string{"/var/lib/postgresql/data/base/1", "/var/log/postgresql", "/var/run/postgresql"}
	if strings.Join(rec.TmpfsPaths, ",") != strings.Join(want, ",") {
		t.Errorf("TmpfsPaths = %v, want %v", rec.TmpfsPaths, want)
	}
	// With no mounts, every observed write is a tmpfs candidate.
	for _, wp := range s.WritablePaths {
		if wp.Disposition != sidecar.DispositionTmpfsCandidate {
			t.Errorf("path %s disposition = %q, want tmpfs_candidate (no mounts)", wp.Path, wp.Disposition)
		}
	}
}

// TestRun_ObserveFSFixtureCompose is the CLI-level end-to-end: `--observe fs`
// with both fixtures emits the read_only/tmpfs compose stanza on stdout.
func TestRun_ObserveFSFixtureCompose(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--observe", "fs",
		"--fixture", "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		"--mounts-fixture", "testdata/postgres/mounts.json",
		"--container", "postgres-1",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	want := "read_only: true\n" +
		"# review: tmpfs entries are writable paths not on a volume;\n" +
		"# move any that must persist to a volume instead.\n" +
		"tmpfs:\n" +
		"  - /var/log/postgresql\n" +
		"  - /var/run/postgresql\n"
	if out.String() != want {
		t.Errorf("output mismatch:\ngot:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestRun_ObserveUnrecognized(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{"--observe", "bogus", "--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "postgres-1"}, &out, &errBuf)
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("exit code = %d, want %d (EX_USAGE)", exit.CodeFor(err), exit.Usage)
	}
}

// TestRun_ObserveFSJSON: `--observe fs --format json` emits the canonical
// sidecar with the fs section populated and the cap section empty.
func TestRun_ObserveFSJSON(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--observe", "fs", "--format", "json",
		"--fixture", "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		"--mounts-fixture", "testdata/postgres/mounts.json",
		"--container", "postgres-1",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	var s sidecar.Sidecar
	if err := json.Unmarshal(out.Bytes(), &s); err != nil {
		t.Fatalf("sidecar JSON did not parse: %v\n%s", err, out.String())
	}
	if s.FSRecommendation == nil || !s.FSRecommendation.ReadOnly {
		t.Errorf("fs_recommendation = %+v, want ReadOnly=true", s.FSRecommendation)
	}
	if len(s.WritablePaths) != 3 {
		t.Errorf("writable_paths len = %d, want 3", len(s.WritablePaths))
	}
	if len(s.Capabilities) != 0 {
		t.Errorf("capabilities = %v, want empty on an fs run", s.Capabilities)
	}
	// A caps-only run must NOT carry the fs keys; assert they're omitted.
	if strings.Contains(out.String(), "fs_recommendation") == false {
		t.Error("expected fs_recommendation key in fs JSON output")
	}
}

// TestRun_ObserveFSOutAndWorkload: --out writes the sidecar and --workload is
// recorded + lifts the no-workload confidence penalty.
func TestRun_ObserveFSOutAndWorkload(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.sh")
	if err := os.WriteFile(wl, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "s.json")
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--observe", "fs", "--out", outFile, "--workload", wl,
		"--fixture", "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		"--mounts-fixture", "testdata/postgres/mounts.json",
		"--container", "postgres-1",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	data, readErr := os.ReadFile(outFile)
	if readErr != nil {
		t.Fatalf("sidecar not written: %v", readErr)
	}
	var s sidecar.Sidecar
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("sidecar file did not parse: %v", err)
	}
	if s.Workload != wl {
		t.Errorf("sidecar workload = %q, want %q", s.Workload, wl)
	}
}

func TestRun_MountsFixtureRequiresFSObserver(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{"--mounts-fixture", "testdata/postgres/mounts.json", "--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "postgres-1"}, &out, &errBuf)
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("exit code = %d, want %d (EX_USAGE)", exit.CodeFor(err), exit.Usage)
	}
}
