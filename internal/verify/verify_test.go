package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/obstest"
)

func TestClassifyVerify_Consistent(t *testing.T) {
	baseline := []string{"CHOWN", "SETUID"}
	obs := obstest.MakeSidecar("postgres:16", "sha256:abc", "exercises/postgres.sh", 600, "CHOWN", "SETUID")
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
	obs := obstest.MakeSidecar("x", "", "", 0, "CHOWN", "SYS_PTRACE")
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
	obs := obstest.MakeSidecar("x", "", "", 0, "CHOWN")
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
	obs := obstest.MakeSidecar("x", "", "", 0, "CHOWN", "SYS_PTRACE")
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
