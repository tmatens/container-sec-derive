package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

const twoReplicaWrites = `
{"syscall":"openat","flags_raw":1,"fpath":"/var/log/app.log","proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"web-1","containerImageName":"web:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"/var/cache/x","proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"web-1","containerImageName":"web:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"/var/log/app.log","proc":{"comm":"app"},"runtime":{"containerId":"bbb222bbb222","containerName":"web-2","containerImageName":"web:1"}}
`

func TestRun_ObserveFSAmbiguousImage(t *testing.T) {
	dir := t.TempDir()
	fix := filepath.Join(dir, "two.ndjson")
	if err := os.WriteFile(fix, []byte(twoReplicaWrites), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	err := Run([]string{"--observe", "fs", "--fixture", fix, "--image", "web:1"}, &out, &errBuf)
	if exit.CodeFor(err) != exit.TargetAmbiguous {
		t.Errorf("exit code = %d, want %d (ambiguous)", exit.CodeFor(err), exit.TargetAmbiguous)
	}

	// With --all-matching the same fixture succeeds.
	out.Reset()
	errBuf.Reset()
	if err := Run([]string{"--observe", "fs", "--fixture", fix, "--image", "web:1", "--all-matching"}, &out, &errBuf); err != nil {
		t.Fatalf("--all-matching run: %v (stderr: %s)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), "read_only: true") {
		t.Errorf("all-matching output unexpected:\n%s", out.String())
	}
}
func TestRun_ObserveFSFixtureCompose(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := Run([]string{
		"--observe", "fs",
		"--fixture", "../../testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		"--mounts-fixture", "../../testdata/postgres/mounts.json",
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
	err := Run([]string{"--observe", "bogus", "--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "postgres-1"}, &out, &errBuf)
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("exit code = %d, want %d (EX_USAGE)", exit.CodeFor(err), exit.Usage)
	}
}
func TestRun_ObserveFSJSON(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := Run([]string{
		"--observe", "fs", "--format", "json",
		"--fixture", "../../testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		"--mounts-fixture", "../../testdata/postgres/mounts.json",
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
func TestRun_ObserveFSOutAndWorkload(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.sh")
	if err := os.WriteFile(wl, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "s.json")
	var out, errBuf bytes.Buffer
	err := Run([]string{
		"--observe", "fs", "--out", outFile, "--workload", wl,
		"--fixture", "../../testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		"--mounts-fixture", "../../testdata/postgres/mounts.json",
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
	err := Run([]string{"--mounts-fixture", "../../testdata/postgres/mounts.json", "--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "postgres-1"}, &out, &errBuf)
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("exit code = %d, want %d (EX_USAGE)", exit.CodeFor(err), exit.Usage)
	}
}
