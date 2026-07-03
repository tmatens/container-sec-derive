package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/format"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// cleanSidecar returns a Sidecar that clears every compose-lint-profile
// acceptance-contract term. Tests that exercise a failing term mutate one
// field on the returned value; everything else stays valid so the
// assertion isolates the condition under test.
func cleanSidecar(t *testing.T, workloadPath string) *sidecar.Sidecar {
	t.Helper()
	s := sidecar.NewSidecar()
	s.Image = "postgres:16"
	s.ImageDigest = "sha256:deadbeef"
	s.Workload = workloadPath
	s.DurationSeconds = 600
	s.ObservedAt = time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	s.Capabilities = []sidecar.Capability{
		{Name: "CHOWN"}, {Name: "DAC_OVERRIDE"}, {Name: "FOWNER"},
		{Name: "SETGID"}, {Name: "SETUID"},
	}
	s.Confidence = sidecar.Confidence{Level: sidecar.ConfidenceModerate}
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
	if err := format.WriteComposeLintProfile(&buf, s, false); err != nil {
		t.Fatalf("format.WriteComposeLintProfile: %v", err)
	}
	got := buf.String()

	// Aggregate envelope: catalog schema_version, normalized image field,
	// validated status, single capabilities dimension. No exploratory markers.
	for _, want := range []string{
		"schema_version: \"1.0\"\n",
		"image: docker.io/library/postgres\n",
		"status: validated\n",
		"dimensions:\n",
		"  capabilities:\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got:\n%s", want, got)
		}
	}
	// cap_drop: [ALL] + cap_add flow-sequence, deterministic order.
	if !strings.Contains(got, "    cap_drop: [ALL]\n") {
		t.Errorf("cap_drop: [ALL] line missing:\n%s", got)
	}
	if !strings.Contains(got, "    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]\n") {
		t.Errorf("cap_add line missing or misordered:\n%s", got)
	}
	// Per-dimension derivation. These are what the catalog gate keys on;
	// missing any of them is a shape regression.
	for _, want := range []string{
		"derivation:",
		"tool: container-sec-derive",
		`tool_version: "0.7.0"`,
		`sidecar_schema_version: "1.5"`,
		"observer: caps",
		"validated_image: docker.io/library/postgres@sha256:deadbeef",
		`validated_date: "2026-04-22"`,
		"duration_seconds: 600",
		"confidence: moderate",
		"validated_via: [bpf-observation]",
		"observation_backend:",
		"ig_version: v0.51.0",
		"gadgets: []",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got:\n%s", want, got)
		}
	}
	// workload_sha256 is a quoted 64-hex string of the committed workload.
	if !strings.Contains(got, "workload_sha256: \"") {
		t.Errorf("workload_sha256 line missing:\n%s", got)
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
		mutate   func(*sidecar.Sidecar)
		wantHint string
	}{
		{"low confidence", func(s *sidecar.Sidecar) { s.Confidence.Level = sidecar.ConfidenceLow }, "confidence.level"},
		{"missing digest", func(s *sidecar.Sidecar) { s.ImageDigest = "" }, "image_digest missing"},
		{"short duration", func(s *sidecar.Sidecar) { s.DurationSeconds = 60 }, "duration_seconds 60 < 300"},
		{"coverage warning present", func(s *sidecar.Sidecar) {
			s.CoverageWarnings = []string{"coverage_warning: entrypoint references `chown` but CHOWN was not observed"}
		}, "coverage_warnings non-empty"},
		{"drop rate at 1%", func(s *sidecar.Sidecar) { s.TraceHealth.DropRate = 0.01 }, "trace_health.drop_rate"},
		{"replica disagreement", func(s *sidecar.Sidecar) { s.Target.ReplicaCapDisagreement = []string{"FOWNER"} }, "replica_cap_disagreement"},
		{"missing workload path", func(s *sidecar.Sidecar) { s.Workload = "" }, "workload path not set"},
		{"unreadable workload", func(s *sidecar.Sidecar) { s.Workload = "/does/not/exist.sh" }, "workload file"},
		{"schema outside major", func(s *sidecar.Sidecar) { s.SchemaVersion = "2.0" }, "schema_version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cleanSidecar(t, writableWorkload(t))
			tc.mutate(s)

			var buf bytes.Buffer
			err := format.WriteComposeLintProfile(&buf, s, false)
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
	s.Confidence.Level = sidecar.ConfidenceLow
	s.CoverageWarnings = []string{"coverage_warning: entrypoint references `chown` but CHOWN was not observed"}

	var buf bytes.Buffer
	if err := format.WriteComposeLintProfile(&buf, s, true); err != nil {
		t.Fatalf("exploratory emit errored: %v", err)
	}
	got := buf.String()

	// status: exploratory with the violations at the top level (schema places
	// acceptance_contract_violations on the document, not under a dimension),
	// and the dimension is still emitted (dimensions is always required).
	if !strings.Contains(got, "status: exploratory\n") {
		t.Errorf("exploratory emit must carry status: exploratory, got:\n%s", got)
	}
	if strings.Contains(got, "status: validated") {
		t.Errorf("exploratory emit must not claim validated:\n%s", got)
	}
	if !strings.Contains(got, "  capabilities:\n") {
		t.Errorf("exploratory emit should still carry the capabilities dimension, got:\n%s", got)
	}
	// Each violation becomes an annotation line under the top-level list.
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

func TestComposeLintImage_Normalizes(t *testing.T) {
	cases := []struct {
		image string
		want  string
	}{
		{"postgres:16", "docker.io/library/postgres"},
		{"postgres", "docker.io/library/postgres"},
		{"docker.io/library/postgres:16", "docker.io/library/postgres"},
		{"linuxserver/radarr", "docker.io/linuxserver/radarr"},
		{"lscr.io/linuxserver/radarr:latest", "lscr.io/linuxserver/radarr"},
		{"ghcr.io/tmatens/container-sec-derive:latest", "ghcr.io/tmatens/container-sec-derive"},
		{"localhost:5000/foo", "localhost:5000/foo"},
		{"postgres@sha256:abc", "docker.io/library/postgres"},
		{"docker.io/library/postgres:16@sha256:abc", "docker.io/library/postgres"},
		{"", "unknown"},
	}
	for _, tc := range cases {
		s := sidecar.NewSidecar()
		s.Image = tc.image
		if got := format.ComposeLintImage(s); got != tc.want {
			t.Errorf("format.ComposeLintImage(%q) = %q, want %q", tc.image, got, tc.want)
		}
	}
}

func TestRun_FormatComposeLintProfile_RefuseSurfacesEXUsage(t *testing.T) {
	// End-to-end: --format compose-lint-profile without --allow-exploratory
	// against a fixture-only run (no digest, no workload) must refuse and
	// exit EX_USAGE. Guards against dispatch silently emitting an empty
	// profile when the contract isn't met.
	var stdout, stderr bytes.Buffer
	err := Run([]string{
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "compose-lint-profile",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected refuse, got stdout:\n%s", stdout.String())
	}
	if code := exit.CodeFor(err); code != exit.Usage {
		t.Errorf("exit code = %d, want %d (exit.Usage)", code, exit.Usage)
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
	// test only guards the Run() dispatch seam.
	var stdout, stderr bytes.Buffer
	err := Run([]string{
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "compose-lint-profile",
		"--allow-exploratory",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("exploratory run: %v (stderr: %s)", err, stderr.String())
	}
	out := stdout.String()
	if !strings.HasPrefix(out, "schema_version: \"1.0\"\n") {
		t.Errorf("run did not start with the catalog schema_version envelope:\n%s", out)
	}
	if !strings.Contains(out, "status: exploratory\n") {
		t.Errorf("exploratory run did not carry status: exploratory:\n%s", out)
	}
	if !strings.Contains(out, "image: docker.io/library/postgres\n") {
		t.Errorf("exploratory run did not normalize the image field:\n%s", out)
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
	err := Run([]string{
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "compose",
		"--allow-exploratory",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected usage error, got stdout:\n%s", stdout.String())
	}
	if code := exit.CodeFor(err); code != exit.Usage {
		t.Errorf("exit code = %d, want %d (exit.Usage)", code, exit.Usage)
	}
}
