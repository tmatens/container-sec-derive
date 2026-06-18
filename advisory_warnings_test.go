package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/obstest"
)

// TestRun_SubAbortDropRateWarnsToStderr exercises the rc bullet 9
// stderr note for 0 < drop_rate < 10%. Pairs the standard sample
// fixture (10 post-filter events for postgres-1) with a stderr fixture
// reporting "lost 1 samples" → drop_rate = 0.1 sits at the abort
// boundary, so we use the broader fixture that records 17 events
// across replicas with --all-matching to keep the rate comfortably
// below 10%.
func TestRun_SubAbortDropRateWarnsToStderr(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--fixture-stderr", "testdata/ig-versions/v0.51.0/low_drop_rate.stderr",
		"--image", "postgres:16",
		"--all-matching",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	stderrStr := errBuf.String()
	if !strings.Contains(stderrStr, "csd: warning:") || !strings.Contains(stderrStr, "drop_rate") {
		t.Errorf("expected sub-abort drop-rate warning on stderr, got:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "below 0.10 abort threshold") {
		t.Errorf("warning should cite the abort threshold:\n%s", stderrStr)
	}
}

func TestRun_NoDropRateNoWarning(t *testing.T) {
	// Drop rate exactly 0 must not produce a warning; clean runs should
	// have clean stderr.
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "drop_rate") {
		t.Errorf("clean run produced unexpected drop_rate warning:\n%s", errBuf.String())
	}
}

func TestRun_AbortDropRateDoesNotDoubleWarn(t *testing.T) {
	// At/above the 10% abort threshold the existing fatal path takes
	// over; the soft warning would be redundant. Asserting the absence
	// of "drop_rate" in stderr keeps the two paths exclusive.
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/high_drop_rate.ndjson",
		"--fixture-stderr", "testdata/ig-versions/v0.51.0/high_drop_rate.stderr",
		"--container", "t",
		"--init-window-ms", "0",
	}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected drop-rate abort error")
	}
	if strings.Contains(errBuf.String(), "csd: warning: trace_health drop_rate") {
		t.Errorf("abort path should not also emit the soft warning:\n%s", errBuf.String())
	}
}

func TestRun_ReplicaDisagreementWarnsToStderr(t *testing.T) {
	// sample.ndjson has two postgres:16 replicas; postgres-1 fires
	// FOWNER post-init-window, postgres-2 doesn't — so --all-matching
	// produces FOWNER in the union with disagreement={FOWNER}.
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--image", "postgres:16",
		"--all-matching",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	stderrStr := errBuf.String()
	if !strings.Contains(stderrStr, "csd: warning: replicas disagree") {
		t.Errorf("expected replica-disagreement warning on stderr, got:\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "FOWNER") {
		t.Errorf("warning should name the disagreed cap (FOWNER):\n%s", stderrStr)
	}
	if !strings.Contains(stderrStr, "--all-matching produced a union profile") {
		t.Errorf("warning should explain the implication:\n%s", stderrStr)
	}
}

func TestRun_PrivilegedPartialDecompositionWarnsToStderr(t *testing.T) {
	// A --observe privileged run must always warn that the decomposition is
	// partial (caps + devices only, no AppArmor/seccomp). json's body carries
	// no `#` caveat, so the stderr advisory is the only guardrail for it —
	// assert it fires here.
	caps := obstest.WriteTemp(t, "caps.ndjson", obstest.PrivCapsFixture)
	dev := obstest.WriteTemp(t, "dev.ndjson", obstest.PrivDevFixture)
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--observe", "privileged",
		"--container", "gpu-1",
		"--fixture", caps,
		"--device-fixture", dev,
		"--init-window-ms", "0",
		"--format", "json",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	stderrStr := errBuf.String()
	if !strings.Contains(stderrStr, "csd: warning:") || !strings.Contains(stderrStr, "security_opt") {
		t.Errorf("expected partial-decomposition security_opt warning on stderr, got:\n%s", stderrStr)
	}
}

func TestRun_NonPrivilegedNoSecurityOptWarning(t *testing.T) {
	// A plain caps run has no privileged_decomposition, so the security_opt
	// advisory must stay silent — it is scoped to --observe privileged.
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "security_opt") {
		t.Errorf("non-privileged run produced spurious security_opt warning:\n%s", errBuf.String())
	}
}

func TestRun_SingleReplicaNoDisagreementWarning(t *testing.T) {
	// --container against a single replica must never emit a
	// disagreement warning (it's structurally undefined for n=1).
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "replicas disagree") {
		t.Errorf("single replica produced spurious disagreement warning:\n%s", errBuf.String())
	}
}
