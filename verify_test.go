package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/obstest"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// makeSidecar builds a minimal valid Sidecar with the named caps plus
// optional knobs. Tests use it instead of inlining literal sidecar
// JSON so a future schema-additive bump touches one helper.
func makeSidecar(image, digest, workload string, durationSeconds int, caps ...string) *sidecar.Sidecar {
	s := sidecar.NewSidecar()
	s.Image = image
	s.ImageDigest = digest
	s.Workload = workload
	s.DurationSeconds = durationSeconds
	for _, c := range caps {
		s.Capabilities = append(s.Capabilities, sidecar.Capability{
			Name:              c,
			EventCount:        1,
			FirstSeenOffsetMs: 0,
			LastSeenOffsetMs:  0,
			CommSamples:       []string{c + "-sample"},
		})
	}
	return s
}

func writeSidecarFile(t *testing.T, dir, name string, s *sidecar.Sidecar) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := writeJSON(f, s); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestClassifyVerify_Consistent(t *testing.T) {
	baseline := []string{"CHOWN", "SETUID"}
	obs := makeSidecar("postgres:16", "sha256:abc", "exercises/postgres.sh", 600, "CHOWN", "SETUID")
	vr, code := classifyVerify(baseline, obs, "/tmp/baseline.json")
	if vr.Outcome != VerifyOutcomeConsistent {
		t.Errorf("outcome = %q, want %q", vr.Outcome, VerifyOutcomeConsistent)
	}
	if code != exit.OK {
		t.Errorf("code = %d, want %d", code, exit.OK)
	}
	if len(vr.NewDenials) != 0 {
		t.Errorf("expected no new denials, got %+v", vr.NewDenials)
	}
	if len(vr.UnusedCaps) != 0 {
		t.Errorf("expected no unused caps, got %v", vr.UnusedCaps)
	}
	if vr.Caveat != VerifyCaveat {
		t.Errorf("caveat must be the canonical string, got %q", vr.Caveat)
	}
	if vr.VerifyOf != "/tmp/baseline.json" {
		t.Errorf("verify_of = %q, want /tmp/baseline.json", vr.VerifyOf)
	}
	if vr.Workload != "exercises/postgres.sh" || vr.DurationSeconds != 600 {
		t.Errorf("observation context not propagated: workload=%q duration=%d", vr.Workload, vr.DurationSeconds)
	}
}

func TestClassifyVerify_Insufficient(t *testing.T) {
	baseline := []string{"CHOWN"}
	obs := makeSidecar("x", "", "", 0, "CHOWN", "SYS_PTRACE")
	vr, code := classifyVerify(baseline, obs, "b.json")
	if vr.Outcome != VerifyOutcomeInsufficient {
		t.Errorf("outcome = %q, want %q", vr.Outcome, VerifyOutcomeInsufficient)
	}
	if code != exit.VerifyInsufficient {
		t.Errorf("code = %d, want %d", code, exit.VerifyInsufficient)
	}
	if len(vr.NewDenials) != 1 || vr.NewDenials[0].Cap != "SYS_PTRACE" {
		t.Errorf("new_denials = %+v, want [SYS_PTRACE]", vr.NewDenials)
	}
	if !obstest.EqualSlice(vr.NewDenials[0].CommSamples, []string{"SYS_PTRACE-sample"}) {
		t.Errorf("comm_samples not propagated: %v", vr.NewDenials[0].CommSamples)
	}
}

func TestClassifyVerify_OverPermissioned(t *testing.T) {
	baseline := []string{"CHOWN", "FOWNER"}
	obs := makeSidecar("x", "", "", 0, "CHOWN")
	vr, code := classifyVerify(baseline, obs, "b.json")
	if vr.Outcome != VerifyOutcomeOverPermissioned {
		t.Errorf("outcome = %q, want %q", vr.Outcome, VerifyOutcomeOverPermissioned)
	}
	if code != exit.VerifyOverPermissioned {
		t.Errorf("code = %d, want %d", code, exit.VerifyOverPermissioned)
	}
	if !obstest.EqualSlice(vr.UnusedCaps, []string{"FOWNER"}) {
		t.Errorf("unused_caps = %v, want [FOWNER]", vr.UnusedCaps)
	}
}

func TestClassifyVerify_InsufficientWinsOverOverPermissioned(t *testing.T) {
	// Both new denials AND unused caps present: insufficient takes
	// precedence because a missing cap is the more actionable signal.
	baseline := []string{"CHOWN", "FOWNER"}
	obs := makeSidecar("x", "", "", 0, "CHOWN", "SYS_PTRACE")
	vr, code := classifyVerify(baseline, obs, "b.json")
	if vr.Outcome != VerifyOutcomeInsufficient {
		t.Errorf("outcome = %q, want %q", vr.Outcome, VerifyOutcomeInsufficient)
	}
	if code != exit.VerifyInsufficient {
		t.Errorf("code = %d, want %d", code, exit.VerifyInsufficient)
	}
	// Unused caps still recorded so the user sees the trim opportunity
	// after they fix the insufficiency.
	if !obstest.EqualSlice(vr.UnusedCaps, []string{"FOWNER"}) {
		t.Errorf("unused_caps still recorded: got %v", vr.UnusedCaps)
	}
}

func TestRunVerify_ConsistentExit0(t *testing.T) {
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "baseline.json",
		makeSidecar("postgres:16", "sha256:abc", "", 0, "CHOWN", "SETUID"))
	op := writeSidecarFile(t, dir, "observation.json",
		makeSidecar("postgres:16", "sha256:abc", "exercises/postgres.sh", 600, "CHOWN", "SETUID"))

	var stdout, stderr bytes.Buffer
	err := run([]string{"verify", "--baseline", bp, "--observation", op}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("verify: %v (stderr=%q)", err, stderr.String())
	}
	var vr VerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &vr); err != nil {
		t.Fatalf("unmarshal stdout: %v\n%s", err, stdout.String())
	}
	if vr.Outcome != VerifyOutcomeConsistent {
		t.Errorf("outcome = %q, want %q", vr.Outcome, VerifyOutcomeConsistent)
	}
	if vr.Caveat == "" {
		t.Errorf("caveat must be present")
	}
}

func TestRunVerify_InsufficientExit10(t *testing.T) {
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "b.json", makeSidecar("x", "", "", 0, "CHOWN"))
	op := writeSidecarFile(t, dir, "o.json", makeSidecar("x", "", "", 0, "CHOWN", "SYS_PTRACE"))
	var stdout, stderr bytes.Buffer
	err := run([]string{"verify", "--baseline", bp, "--observation", op}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for insufficient outcome")
	}
	if got := exit.CodeFor(err); got != exit.VerifyInsufficient {
		t.Errorf("exit = %d, want %d", got, exit.VerifyInsufficient)
	}
}

func TestRunVerify_OverPermissionedExit11(t *testing.T) {
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "b.json", makeSidecar("x", "", "", 0, "CHOWN", "FOWNER"))
	op := writeSidecarFile(t, dir, "o.json", makeSidecar("x", "", "", 0, "CHOWN"))
	var stdout, stderr bytes.Buffer
	err := run([]string{"verify", "--baseline", bp, "--observation", op}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for over_permissioned outcome")
	}
	if got := exit.CodeFor(err); got != exit.VerifyOverPermissioned {
		t.Errorf("exit = %d, want %d", got, exit.VerifyOverPermissioned)
	}
}

func TestRunVerify_RequiresBaselineEXUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"verify"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected EX_USAGE for missing --baseline")
	}
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("exit = %d, want %d", exit.CodeFor(err), exit.Usage)
	}
}

func TestRunVerify_RequiresObservationOrSelectorEXUsage(t *testing.T) {
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "b.json", makeSidecar("x", "", "", 0, "CHOWN"))
	var stdout, stderr bytes.Buffer
	err := run([]string{"verify", "--baseline", bp}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected EX_USAGE for --baseline without --observation or run-mode selector")
	}
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("exit = %d, want %d", exit.CodeFor(err), exit.Usage)
	}
	if !strings.Contains(err.Error(), "--observation") {
		t.Errorf("error should guide the user toward both modes: %v", err)
	}
}

func TestRunVerify_ObservationAndRunModeMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "b.json", makeSidecar("x", "", "", 0, "CHOWN"))
	op := writeSidecarFile(t, dir, "o.json", makeSidecar("x", "", "", 0, "CHOWN"))
	var stdout, stderr bytes.Buffer
	err := run([]string{"verify", "--baseline", bp, "--observation", op,
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected EX_USAGE for mixing --observation with run-mode flags")
	}
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("exit = %d, want %d", exit.CodeFor(err), exit.Usage)
	}
}

func TestRunVerify_RunMode_FixtureConsistent(t *testing.T) {
	// Run-mode against the v0.51.0 sample fixture. Single-replica
	// (postgres-1) cap set is [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]
	// (matches the existing TestRun_FixtureMode assertion). A baseline
	// listing the same caps must classify as consistent.
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "b.json",
		makeSidecar("postgres:16", "", "", 0, "CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"))

	var stdout, stderr bytes.Buffer
	err := run([]string{"verify", "--baseline", bp,
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("verify run-mode: %v (stderr=%q)", err, stderr.String())
	}
	var vr VerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &vr); err != nil {
		t.Fatalf("unmarshal stdout: %v\n%s", err, stdout.String())
	}
	if vr.Outcome != VerifyOutcomeConsistent {
		t.Errorf("outcome = %q, want %q (denials=%+v unused=%v)",
			vr.Outcome, VerifyOutcomeConsistent, vr.NewDenials, vr.UnusedCaps)
	}
}

func TestRunVerify_RunMode_FixtureInsufficientWhenBaselineTooSmall(t *testing.T) {
	// Same fixture, but baseline only lists CHOWN -- the postgres-1
	// observation will surface DAC_OVERRIDE/FOWNER/SETGID/SETUID as new
	// denials and the outcome must be insufficient (exit 10).
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "b.json",
		makeSidecar("postgres:16", "", "", 0, "CHOWN"))

	var stdout, stderr bytes.Buffer
	err := run([]string{"verify", "--baseline", bp,
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected nonzero exit for insufficient outcome")
	}
	if got := exit.CodeFor(err); got != exit.VerifyInsufficient {
		t.Errorf("exit = %d, want %d", got, exit.VerifyInsufficient)
	}
	var vr VerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &vr); err != nil {
		t.Fatalf("unmarshal stdout: %v\n%s", err, stdout.String())
	}
	denialNames := make([]string, 0, len(vr.NewDenials))
	for _, d := range vr.NewDenials {
		denialNames = append(denialNames, d.Cap)
	}
	want := []string{"DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}
	if !obstest.EqualSlice(denialNames, want) {
		t.Errorf("new_denials = %v, want %v", denialNames, want)
	}
}

func TestRunVerify_RunMode_FixtureOverPermissionedWhenBaselineTooLarge(t *testing.T) {
	// Baseline lists a cap (SYS_PTRACE) the fixture observation does not
	// produce -- outcome must be over_permissioned.
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "b.json",
		makeSidecar("postgres:16", "", "", 0, "CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "SYS_PTRACE"))

	var stdout, stderr bytes.Buffer
	err := run([]string{"verify", "--baseline", bp,
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected nonzero exit for over_permissioned outcome")
	}
	if got := exit.CodeFor(err); got != exit.VerifyOverPermissioned {
		t.Errorf("exit = %d, want %d", got, exit.VerifyOverPermissioned)
	}
	var vr VerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &vr); err != nil {
		t.Fatalf("unmarshal stdout: %v\n%s", err, stdout.String())
	}
	if !obstest.EqualSlice(vr.UnusedCaps, []string{"SYS_PTRACE"}) {
		t.Errorf("unused_caps = %v, want [SYS_PTRACE]", vr.UnusedCaps)
	}
}

func TestRunVerify_MissingBaselineFileEXUsage(t *testing.T) {
	dir := t.TempDir()
	op := writeSidecarFile(t, dir, "o.json", makeSidecar("x", "", "", 0, "CHOWN"))
	var stdout, stderr bytes.Buffer
	err := run([]string{"verify", "--baseline", "/nonexistent/x.json", "--observation", op}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing baseline file")
	}
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("exit = %d, want %d", exit.CodeFor(err), exit.Usage)
	}
}

func TestLoadSidecar_RejectsCrossMajorSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "future.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"2.0","capabilities":[]}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadSidecar(path)
	if err == nil {
		t.Fatal("expected cross-major rejection")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error should name the schema_version mismatch: %v", err)
	}
}

func TestLoadSidecar_RejectsMissingSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noschema.json")
	if err := os.WriteFile(path, []byte(`{"capabilities":[]}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadSidecar(path)
	if err == nil {
		t.Fatal("expected schema-missing rejection")
	}
}
