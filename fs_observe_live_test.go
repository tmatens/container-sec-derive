package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/ig"
)

// fakeIGRun writes a fake `ig` whose `run` subcommand cats prepared stdout
// (trace_open NDJSON) and stderr (ig diagnostics) files, so observeWrites can
// be exercised without a real ig binary or BPF — the fs analog of
// fakeIGBinary's version stub, extended to the run path. `version` reports
// PinnedIGVersion so the same fake also clears checkIGVersion if a caller
// routes through produceFSObservation.
func fakeIGRun(t *testing.T, stdoutNDJSON, stderrText string) string {
	t.Helper()
	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.ndjson")
	errFile := filepath.Join(dir, "err.txt")
	if err := os.WriteFile(outFile, []byte(stdoutNDJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errFile, []byte(stderrText), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ig-fake")
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  version) echo " + ig.PinnedIGVersion + "; exit 0;;\n" +
		"  run) cat " + outFile + "; cat " + errFile + " >&2; exit 0;;\n" +
		"esac\n" +
		"exit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestObserveWrites_FakeIG covers the live spawn → parse → drop-accounting path
// (0% under unit tests before this): the fake ig streams trace_open events and
// a "lost N samples" stderr line; observeWrites must aggregate the write-intent
// opens and surface the loss count on writeObservation.Dropped.
func TestObserveWrites_FakeIG(t *testing.T) {
	nd := strings.Join([]string{
		`{"syscall":"openat","flags_raw":1,"fpath":"/var/log/app.log","proc":{"comm":"app"},"runtime":{"containerId":"c1","containerName":"web","containerImageName":"web:1"}}`,
		`{"syscall":"openat","flags_raw":0,"fpath":"/etc/passwd","proc":{"comm":"app"},"runtime":{"containerId":"c1","containerName":"web","containerImageName":"web:1"}}`,
	}, "\n")
	ig := fakeIGRun(t, nd, "level=info msg=starting\nlost 3 samples\n")

	obs, err := observeWrites(context.Background(), ig, attrib.Opts{}, io.Discard)
	if err != nil {
		t.Fatalf("observeWrites: %v", err)
	}
	if obs.EventCount != 1 {
		t.Errorf("EventCount = %d, want 1 (the read-only /etc/passwd open is excluded)", obs.EventCount)
	}
	if len(obs.Paths) != 1 || obs.Paths[0] != "/var/log/app.log" {
		t.Errorf("Paths = %v, want [/var/log/app.log]", obs.Paths)
	}
	if obs.Dropped != 3 {
		t.Errorf("Dropped = %d, want 3 (parsed from 'lost 3 samples')", obs.Dropped)
	}
}

// TestObserveWrites_IGMissing: a missing ig binary maps to exit.IGMissing,
// matching the capability observe() contract.
func TestObserveWrites_IGMissing(t *testing.T) {
	_, err := observeWrites(context.Background(), "/nonexistent/csd-ig-fs-test", attrib.Opts{}, io.Discard)
	if err == nil {
		t.Fatal("expected missing-binary error")
	}
	if exit.CodeFor(err) != exit.IGMissing {
		t.Errorf("exit = %d, want exit.IGMissing (%d); err=%v", exit.CodeFor(err), exit.IGMissing, err)
	}
}
