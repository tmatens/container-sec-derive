package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cleanSidecar returns a Sidecar that clears every compose-lint-profile
// acceptance-contract term. Tests that exercise a failing term mutate one
// field on the returned value; everything else stays valid so the
// assertion isolates the condition under test.
func cleanSidecar(t *testing.T, workloadPath string) *Sidecar {
	t.Helper()
	s := NewSidecar()
	s.Image = "postgres:16"
	s.ImageDigest = "sha256:deadbeef"
	s.Workload = workloadPath
	s.DurationSeconds = 600
	s.ObservedAt = time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	s.Capabilities = []Capability{
		{Name: "CHOWN"}, {Name: "DAC_OVERRIDE"}, {Name: "FOWNER"},
		{Name: "SETGID"}, {Name: "SETUID"},
	}
	s.Confidence = Confidence{Level: ConfidenceModerate}
	return s
}

// writableWorkload writes a placeholder workload script into tempdir and
// returns the path. Every clean-path test needs one because the contract
// checks os.Stat at emit time.
func writableWorkload(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "workload.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write workload: %v", err)
	}
	return p
}

func TestWriteComposeLintProfile_CleanEmitsContributableEntry(t *testing.T) {
	s := cleanSidecar(t, writableWorkload(t))

	var buf bytes.Buffer
	if err := writeComposeLintProfile(&buf, s, false); err != nil {
		t.Fatalf("writeComposeLintProfile: %v", err)
	}
	got := buf.String()

	// Top-level key: short name derived from the image ref, no exploratory prefix.
	if !strings.HasPrefix(got, "postgres:\n") {
		t.Errorf("expected bare 'postgres:' top-level key, got:\n%s", got)
	}
	if strings.Contains(got, "exploratory:") {
		t.Errorf("clean emit must not produce exploratory: block:\n%s", got)
	}
	// Caps flow-sequence, deterministic order.
	if !strings.Contains(got, "caps: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]") {
		t.Errorf("caps line missing or misordered:\n%s", got)
	}
	// Derivation + validated_* block. These are what the receiving catalog
	// keys on; missing any of them is a shape regression.
	for _, want := range []string{
		"derivation:",
		"tool: container-sec-derive",
		`schema_version: "1.0"`,
		"duration_seconds: 600",
		"confidence: moderate",
		"validated_image: postgres:16@sha256:deadbeef",
		"validated_date: 2026-04-22",
		"validated_via: [bpf-observation]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "acceptance_contract_violations:") {
		t.Errorf("clean emit must not annotate violations:\n%s", got)
	}
}

func TestWriteComposeLintProfile_RefusesOnUnmetContract(t *testing.T) {
	// Each subtest mutates exactly one field so the failing term is
	// attributable; every other field stays at its clean-sidecar value.
	cases := []struct {
		name     string
		mutate   func(*Sidecar)
		wantHint string
	}{
		{"low confidence", func(s *Sidecar) { s.Confidence.Level = ConfidenceLow }, "confidence.level"},
		{"missing digest", func(s *Sidecar) { s.ImageDigest = "" }, "image_digest missing"},
		{"short duration", func(s *Sidecar) { s.DurationSeconds = 60 }, "duration_seconds 60 < 300"},
		{"coverage warning present", func(s *Sidecar) {
			s.CoverageWarnings = []string{"coverage_warning: entrypoint references `chown` but CHOWN was not observed"}
		}, "coverage_warnings non-empty"},
		{"drop rate at 1%", func(s *Sidecar) { s.TraceHealth.DropRate = 0.01 }, "trace_health.drop_rate"},
		{"replica disagreement", func(s *Sidecar) { s.Target.ReplicaCapDisagreement = []string{"FOWNER"} }, "replica_cap_disagreement"},
		{"missing workload path", func(s *Sidecar) { s.Workload = "" }, "workload path not set"},
		{"unreadable workload", func(s *Sidecar) { s.Workload = "/does/not/exist.sh" }, "workload file"},
		{"schema outside major", func(s *Sidecar) { s.SchemaVersion = "2.0" }, "schema_version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cleanSidecar(t, writableWorkload(t))
			tc.mutate(s)

			var buf bytes.Buffer
			err := writeComposeLintProfile(&buf, s, false)
			if err == nil {
				t.Fatalf("expected refuse, got output:\n%s", buf.String())
			}
			if !strings.Contains(err.Error(), tc.wantHint) {
				t.Errorf("error %q should name the failing term %q", err.Error(), tc.wantHint)
			}
			if buf.Len() != 0 {
				t.Errorf("refuse path must not write to stdout, got:\n%s", buf.String())
			}
		})
	}
}

func TestWriteComposeLintProfile_ExploratoryAnnotatesViolations(t *testing.T) {
	s := cleanSidecar(t, writableWorkload(t))
	s.Confidence.Level = ConfidenceLow
	s.CoverageWarnings = []string{"coverage_warning: entrypoint references `chown` but CHOWN was not observed"}

	var buf bytes.Buffer
	if err := writeComposeLintProfile(&buf, s, true); err != nil {
		t.Fatalf("exploratory emit errored: %v", err)
	}
	got := buf.String()

	if !strings.HasPrefix(got, "exploratory:\n") {
		t.Errorf("exploratory emit must start with exploratory: key, got:\n%s", got)
	}
	// Service key nested under exploratory:, two-space indented.
	if !strings.Contains(got, "\n  postgres:\n") {
		t.Errorf("exploratory emit should nest 'postgres:' under exploratory:, got:\n%s", got)
	}
	// Each violation becomes an annotation line.
	if !strings.Contains(got, "acceptance_contract_violations:") {
		t.Errorf("exploratory emit should include acceptance_contract_violations block:\n%s", got)
	}
	if !strings.Contains(got, "confidence.level") {
		t.Errorf("exploratory annotations should name low-confidence violation:\n%s", got)
	}
	if !strings.Contains(got, "coverage_warnings non-empty") {
		t.Errorf("exploratory annotations should name coverage-warnings violation:\n%s", got)
	}
}

func TestComposeLintKey_StripsRegistryAndTag(t *testing.T) {
	cases := []struct {
		image string
		want  string
	}{
		{"postgres:16", "postgres"},
		{"postgres", "postgres"},
		{"docker.io/library/postgres:16", "postgres"},
		{"ghcr.io/tmatens/container-sec-derive:latest", "container-sec-derive"},
		{"postgres@sha256:abc", "postgres"},
		{"docker.io/library/postgres:16@sha256:abc", "postgres"},
		{"", "unknown"},
	}
	for _, tc := range cases {
		s := NewSidecar()
		s.Image = tc.image
		if got := composeLintKey(s); got != tc.want {
			t.Errorf("composeLintKey(%q) = %q, want %q", tc.image, got, tc.want)
		}
	}
}

func TestRun_FormatComposeLintProfile_RefuseSurfacesEXUsage(t *testing.T) {
	// End-to-end: --format compose-lint-profile without --allow-exploratory
	// against a fixture-only run (no digest, no workload) must refuse and
	// exit EX_USAGE. Guards against dispatch silently emitting an empty
	// profile when the contract isn't met.
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "compose-lint-profile",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected refuse, got stdout:\n%s", stdout.String())
	}
	if code := exitCodeFor(err); code != ExitUsage {
		t.Errorf("exit code = %d, want %d (ExitUsage)", code, ExitUsage)
	}
	if stdout.Len() != 0 {
		t.Errorf("refuse path must not write to stdout, got:\n%s", stdout.String())
	}
	if !strings.Contains(err.Error(), "image_digest missing") {
		t.Errorf("error should name the missing-digest violation, got: %v", err)
	}
}

func TestRun_FormatComposeLintProfile_ExploratoryEndToEnd(t *testing.T) {
	// End-to-end exploratory path. Asserts dispatch wires the flag and
	// stdout carries an exploratory: block with the postgres key nested
	// inside. Field-level formatting is covered by unit tests -- this
	// test only guards the run() dispatch seam.
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "compose-lint-profile",
		"--allow-exploratory",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("exploratory run: %v (stderr: %s)", err, stderr.String())
	}
	out := stdout.String()
	if !strings.HasPrefix(out, "exploratory:\n") {
		t.Errorf("exploratory run did not start with exploratory: block:\n%s", out)
	}
	if !strings.Contains(out, "  postgres:\n") {
		t.Errorf("exploratory run did not nest postgres: under exploratory::\n%s", out)
	}
	if !strings.Contains(out, "acceptance_contract_violations:") {
		t.Errorf("exploratory run missing violations annotation:\n%s", out)
	}
}

func TestRun_AllowExploratoryRejectedForOtherFormats(t *testing.T) {
	// --allow-exploratory is compose-lint-profile-only. Passing it with
	// any other --format must fail at flag-validation time so users don't
	// assume it has some silent cross-formatter effect.
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "compose",
		"--allow-exploratory",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected usage error, got stdout:\n%s", stdout.String())
	}
	if code := exitCodeFor(err); code != ExitUsage {
		t.Errorf("exit code = %d, want %d (ExitUsage)", code, ExitUsage)
	}
}
