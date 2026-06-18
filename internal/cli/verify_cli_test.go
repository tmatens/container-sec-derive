package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/format"
	"github.com/tmatens/container-sec-derive/internal/obstest"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
	"github.com/tmatens/container-sec-derive/internal/verify"
)

func writeSidecarFile(t *testing.T, dir, name string, s *sidecar.Sidecar) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := format.WriteJSON(f, s); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestRunVerify_ConsistentExit0(t *testing.T) {
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "baseline.json",
		obstest.MakeSidecar("postgres:16", "sha256:abc", "", 0, "CHOWN", "SETUID"))
	op := writeSidecarFile(t, dir, "observation.json",
		obstest.MakeSidecar("postgres:16", "sha256:abc", "exercises/postgres.sh", 600, "CHOWN", "SETUID"))

	var stdout, stderr bytes.Buffer
	err := Run([]string{"verify", "--baseline", bp, "--observation", op}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("verify: %v (stderr=%q)", err, stderr.String())
	}
	var vr verify.VerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &vr); err != nil {
		t.Fatalf("unmarshal stdout: %v\n%s", err, stdout.String())
	}
	if vr.Outcome != verify.VerifyOutcomeConsistent {
		t.Errorf("outcome = %q, want %q", vr.Outcome, verify.VerifyOutcomeConsistent)
	}
	if vr.Caveat == "" {
		t.Errorf("caveat must be present")
	}
}

func TestRunVerify_InsufficientExit10(t *testing.T) {
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "b.json", obstest.MakeSidecar("x", "", "", 0, "CHOWN"))
	op := writeSidecarFile(t, dir, "o.json", obstest.MakeSidecar("x", "", "", 0, "CHOWN", "SYS_PTRACE"))
	var stdout, stderr bytes.Buffer
	err := Run([]string{"verify", "--baseline", bp, "--observation", op}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for insufficient outcome")
	}
	if got := exit.CodeFor(err); got != exit.VerifyInsufficient {
		t.Errorf("exit = %d, want %d", got, exit.VerifyInsufficient)
	}
}

func TestRunVerify_OverPermissionedExit11(t *testing.T) {
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "b.json", obstest.MakeSidecar("x", "", "", 0, "CHOWN", "FOWNER"))
	op := writeSidecarFile(t, dir, "o.json", obstest.MakeSidecar("x", "", "", 0, "CHOWN"))
	var stdout, stderr bytes.Buffer
	err := Run([]string{"verify", "--baseline", bp, "--observation", op}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for over_permissioned outcome")
	}
	if got := exit.CodeFor(err); got != exit.VerifyOverPermissioned {
		t.Errorf("exit = %d, want %d", got, exit.VerifyOverPermissioned)
	}
}

func TestRunVerify_RequiresBaselineEXUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"verify"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected EX_USAGE for missing --baseline")
	}
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("exit = %d, want %d", exit.CodeFor(err), exit.Usage)
	}
}

func TestRunVerify_RequiresObservationOrSelectorEXUsage(t *testing.T) {
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "b.json", obstest.MakeSidecar("x", "", "", 0, "CHOWN"))
	var stdout, stderr bytes.Buffer
	err := Run([]string{"verify", "--baseline", bp}, &stdout, &stderr)
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
	bp := writeSidecarFile(t, dir, "b.json", obstest.MakeSidecar("x", "", "", 0, "CHOWN"))
	op := writeSidecarFile(t, dir, "o.json", obstest.MakeSidecar("x", "", "", 0, "CHOWN"))
	var stdout, stderr bytes.Buffer
	err := Run([]string{"verify", "--baseline", bp, "--observation", op,
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson"}, &stdout, &stderr)
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
		obstest.MakeSidecar("postgres:16", "", "", 0, "CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"))

	var stdout, stderr bytes.Buffer
	err := Run([]string{"verify", "--baseline", bp,
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("verify run-mode: %v (stderr=%q)", err, stderr.String())
	}
	var vr verify.VerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &vr); err != nil {
		t.Fatalf("unmarshal stdout: %v\n%s", err, stdout.String())
	}
	if vr.Outcome != verify.VerifyOutcomeConsistent {
		t.Errorf("outcome = %q, want %q (denials=%+v unused=%v)",
			vr.Outcome, verify.VerifyOutcomeConsistent, vr.NewDenials, vr.UnusedCaps)
	}
}

func TestRunVerify_RunMode_FixtureInsufficientWhenBaselineTooSmall(t *testing.T) {
	// Same fixture, but baseline only lists CHOWN -- the postgres-1
	// observation will surface DAC_OVERRIDE/FOWNER/SETGID/SETUID as new
	// denials and the outcome must be insufficient (exit 10).
	dir := t.TempDir()
	bp := writeSidecarFile(t, dir, "b.json",
		obstest.MakeSidecar("postgres:16", "", "", 0, "CHOWN"))

	var stdout, stderr bytes.Buffer
	err := Run([]string{"verify", "--baseline", bp,
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected nonzero exit for insufficient outcome")
	}
	if got := exit.CodeFor(err); got != exit.VerifyInsufficient {
		t.Errorf("exit = %d, want %d", got, exit.VerifyInsufficient)
	}
	var vr verify.VerifyResult
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
		obstest.MakeSidecar("postgres:16", "", "", 0, "CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "SYS_PTRACE"))

	var stdout, stderr bytes.Buffer
	err := Run([]string{"verify", "--baseline", bp,
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected nonzero exit for over_permissioned outcome")
	}
	if got := exit.CodeFor(err); got != exit.VerifyOverPermissioned {
		t.Errorf("exit = %d, want %d", got, exit.VerifyOverPermissioned)
	}
	var vr verify.VerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &vr); err != nil {
		t.Fatalf("unmarshal stdout: %v\n%s", err, stdout.String())
	}
	if !obstest.EqualSlice(vr.UnusedCaps, []string{"SYS_PTRACE"}) {
		t.Errorf("unused_caps = %v, want [SYS_PTRACE]", vr.UnusedCaps)
	}
}

func TestRunVerify_MissingBaselineFileEXUsage(t *testing.T) {
	dir := t.TempDir()
	op := writeSidecarFile(t, dir, "o.json", obstest.MakeSidecar("x", "", "", 0, "CHOWN"))
	var stdout, stderr bytes.Buffer
	err := Run([]string{"verify", "--baseline", "/nonexistent/x.json", "--observation", op}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing baseline file")
	}
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("exit = %d, want %d", exit.CodeFor(err), exit.Usage)
	}
}
