package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fsPatchCompose = `services:
  web:
    image: nginx
    ports:
      - "80:80"
`

func TestWriteFSComposePatch_InsertsReadOnlyAndTmpfs(t *testing.T) {
	var b bytes.Buffer
	rec := fsRecommendation{ReadOnly: true, TmpfsPaths: []string{"/run", "/tmp"}}
	if err := writeFSComposePatch(&b, rec, []byte(fsPatchCompose), "compose.yml", "web"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"+    read_only: true", "+    tmpfs:", "+      - /run", "+      - /tmp", "--- a/compose.yml", "@@ "} {
		if !strings.Contains(out, want) {
			t.Errorf("patch missing %q:\n%s", want, out)
		}
	}
}

// An empty derived tmpfs set must leave an existing tmpfs block untouched
// (issue-#77 foot-gun): we only add read_only, never propose deleting tmpfs.
func TestWriteFSComposePatch_EmptyTmpfsKeepsExisting(t *testing.T) {
	const in = `services:
  web:
    image: nginx
    tmpfs:
      - /var/cache
`
	var b bytes.Buffer
	rec := fsRecommendation{ReadOnly: true} // no tmpfs candidates
	if err := writeFSComposePatch(&b, rec, []byte(in), "compose.yml", "web"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "+    read_only: true") {
		t.Errorf("expected read_only addition:\n%s", out)
	}
	if strings.Contains(out, "-      - /var/cache") {
		t.Errorf("must not remove the user's existing tmpfs:\n%s", out)
	}
}

func TestWriteFSComposePatch_UnknownService(t *testing.T) {
	var b bytes.Buffer
	err := writeFSComposePatch(&b, fsRecommendation{ReadOnly: true}, []byte(fsPatchCompose), "compose.yml", "nope")
	if err == nil {
		t.Error("expected error for unknown service")
	}
}

// cleanFSSidecar builds a sidecar that clears the compose-lint acceptance
// contract, so the formatter emits a non-exploratory entry.
func cleanFSSidecar(t *testing.T) *Sidecar {
	t.Helper()
	wl := filepath.Join(t.TempDir(), "wl.sh")
	if err := os.WriteFile(wl, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewSidecar()
	s.Image = "postgres:16"
	s.ImageDigest = "sha256:abc"
	s.Workload = wl
	s.DurationSeconds = 600
	s.ObservedAt = time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	s.Confidence.Level = ConfidenceModerate
	s.FSRecommendation = &fsRecommendation{ReadOnly: true, TmpfsPaths: []string{"/var/log/postgresql", "/var/run/postgresql"}}
	return s
}

func TestWriteFSComposeLintProfile_Clean(t *testing.T) {
	var b bytes.Buffer
	if err := writeFSComposeLintProfile(&b, cleanFSSidecar(t), false); err != nil {
		t.Fatalf("clean profile rejected: %v", err)
	}
	out := b.String()
	for _, want := range []string{
		"postgres:",
		"read_only: true",
		"tmpfs: [/var/log/postgresql, /var/run/postgresql]",
		"observer: fs",
		"validated_image: postgres:16@sha256:abc",
		"validated_via: [bpf-observation]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("clean profile missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "exploratory:") {
		t.Errorf("clean profile should not be exploratory:\n%s", out)
	}
}

func TestWriteFSComposeLintProfile_ContractGate(t *testing.T) {
	// A sparse fixture-derived sidecar (no digest, low confidence) fails the
	// gate: rejected without --allow-exploratory, emitted with it.
	s, err := produceFSObservation(fsPipelineOpts{
		AggregateOpts: aggregateOpts{Container: "postgres-1"},
		Fixture:       "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		MountsFixture: "testdata/postgres/mounts.json",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := writeFSComposeLintProfile(&b, s, false); err == nil {
		t.Error("expected contract rejection for sparse sidecar")
	}
	b.Reset()
	if err := writeFSComposeLintProfile(&b, s, true); err != nil {
		t.Fatalf("exploratory emit failed: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "exploratory:") || !strings.Contains(out, "acceptance_contract_violations:") {
		t.Errorf("exploratory output missing annotation:\n%s", out)
	}
}

// TestRun_ObserveFSComposePatchAndProfile drives both compose-anchored
// formatters through run() end-to-end.
func TestRun_ObserveFSComposePatchAndProfile(t *testing.T) {
	dir := t.TempDir()
	composeFile := filepath.Join(dir, "compose.yml")
	if err := os.WriteFile(composeFile, []byte(fsPatchCompose), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{
		"--observe", "fs",
		"--fixture", "testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		"--mounts-fixture", "testdata/postgres/mounts.json",
		"--container", "postgres-1",
	}

	// compose-patch
	var out, errBuf bytes.Buffer
	args := append(append([]string{}, base...), "--format", "compose-patch", "--compose-in", composeFile, "--service", "web")
	if err := run(args, &out, &errBuf); err != nil {
		t.Fatalf("compose-patch run: %v (stderr: %s)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), "+    read_only: true") {
		t.Errorf("compose-patch output unexpected:\n%s", out.String())
	}

	// compose-patch without --service is EX_USAGE
	out.Reset()
	errBuf.Reset()
	bad := append(append([]string{}, base...), "--format", "compose-patch", "--compose-in", composeFile)
	if exitCodeFor(run(bad, &out, &errBuf)) != ExitUsage {
		t.Error("compose-patch without --service should be EX_USAGE")
	}

	// compose-lint-profile (sparse fixture → contract fails; --allow-exploratory emits)
	out.Reset()
	errBuf.Reset()
	prof := append(append([]string{}, base...), "--format", "compose-lint-profile", "--allow-exploratory")
	if err := run(prof, &out, &errBuf); err != nil {
		t.Fatalf("exploratory profile run: %v (stderr: %s)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), "read_only: true") || !strings.Contains(out.String(), "exploratory:") {
		t.Errorf("exploratory profile output unexpected:\n%s", out.String())
	}
}
