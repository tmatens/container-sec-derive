package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	rec, err := produceFSObservation(fsPipelineOpts{
		AggregateOpts: aggregateOpts{Container: "postgres-1"},
		Fixture:       "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		MountsFixture: "testdata/postgres/mounts.json",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.ReadOnly {
		t.Error("ReadOnly = false, want true")
	}
	wantTmpfs := []string{"/var/log/postgresql", "/var/run/postgresql"}
	if strings.Join(rec.TmpfsPaths, ",") != strings.Join(wantTmpfs, ",") {
		t.Errorf("TmpfsPaths = %v, want %v", rec.TmpfsPaths, wantTmpfs)
	}
	wantCovered := []string{"/var/lib/postgresql/data/base/1/1259"}
	if strings.Join(rec.VolumeCovered, ",") != strings.Join(wantCovered, ",") {
		t.Errorf("VolumeCovered = %v, want %v", rec.VolumeCovered, wantCovered)
	}
}

// TestProduceFSObservationNoMountsFixture: hermetic fixture mode with no
// --mounts-fixture has no mount config, so every write becomes a tmpfs
// candidate (the data write is no longer volume-covered).
func TestProduceFSObservationNoMountsFixture(t *testing.T) {
	rec, err := produceFSObservation(fsPipelineOpts{
		AggregateOpts: aggregateOpts{Container: "postgres-1"},
		Fixture:       "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.VolumeCovered) != 0 {
		t.Errorf("VolumeCovered = %v, want empty (no mounts supplied)", rec.VolumeCovered)
	}
	want := []string{"/var/lib/postgresql/data/base/1", "/var/log/postgresql", "/var/run/postgresql"}
	if strings.Join(rec.TmpfsPaths, ",") != strings.Join(want, ",") {
		t.Errorf("TmpfsPaths = %v, want %v", rec.TmpfsPaths, want)
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
	if exitCodeFor(err) != ExitUsage {
		t.Errorf("exit code = %d, want %d (EX_USAGE)", exitCodeFor(err), ExitUsage)
	}
}

func TestRun_ObserveFSRejectsNonComposeFormat(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{"--observe", "fs", "--format", "json", "--fixture", "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson", "--container", "postgres-1"}, &out, &errBuf)
	if exitCodeFor(err) != ExitUsage {
		t.Errorf("exit code = %d, want %d (EX_USAGE)", exitCodeFor(err), ExitUsage)
	}
}

func TestRun_ObserveFSRejectsOutAndWorkload(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.sh")
	if err := os.WriteFile(wl, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--observe", "fs", "--out", filepath.Join(dir, "s.json"), "--fixture", "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson", "--container", "postgres-1"},
		{"--observe", "fs", "--workload", wl, "--fixture", "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson", "--container", "postgres-1"},
	} {
		var out, errBuf bytes.Buffer
		err := run(args, &out, &errBuf)
		if exitCodeFor(err) != ExitUsage {
			t.Errorf("args %v: exit code = %d, want %d (EX_USAGE)", args, exitCodeFor(err), ExitUsage)
		}
	}
}

func TestRun_MountsFixtureRequiresFSObserver(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{"--mounts-fixture", "testdata/postgres/mounts.json", "--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "postgres-1"}, &out, &errBuf)
	if exitCodeFor(err) != ExitUsage {
		t.Errorf("exit code = %d, want %d (EX_USAGE)", exitCodeFor(err), ExitUsage)
	}
}
