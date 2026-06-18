package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/format"
	"github.com/tmatens/container-sec-derive/internal/obstest"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// This file closes the v0.4 capadd test gaps the #120 deep review flagged
// (TG1–TG5): the Run()-level CLI was 0% covered, computeCapaddConfidence had no
// dedicated test, the live observeCapadd/observeDevices paths were 0%, and
// multi-replica + negative/contract paths were untested.

const capaddGranted = "SYS_ADMIN,NET_RAW,SYS_MODULE,SYS_PTRACE"
const capaddFixture = "../../testdata/capadd/sample.ndjson"
const capaddFixtureContainer = "aabbccddeeff0011"

// runCapadd drives Run() against the capadd fixture with the given extra args
// and returns stdout + the run error.
func runCapadd(t *testing.T, extra ...string) (string, error) {
	t.Helper()
	args := append([]string{
		"--fixture", capaddFixture,
		"--container", capaddFixtureContainer,
		"--observe", "capadd",
	}, extra...)
	var out, errBuf bytes.Buffer
	err := Run(args, &out, &errBuf)
	return out.String(), err
}

// TestRun_CapaddAllFormats is TG1: produceCapaddObservation + every formatter
// driven end-to-end through Run(), in granted mode (--cap-add). Each format must
// emit without error and produce its characteristic output.
func TestRun_CapaddAllFormats(t *testing.T) {
	dir := t.TempDir()
	composeIn := filepath.Join(dir, "compose.yaml")
	if err := writeFile(composeIn, "services:\n  app:\n    image: x\n    cap_add:\n      - SYS_ADMIN\n      - NET_RAW\n"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		format string
		extra  []string
		want   string // substring the output must contain
	}{
		{"compose", nil, "cap_add"},
		{"docker-run", nil, "--cap-add"},
		{"json", nil, `"capadd_validation"`},
		{"k8s", nil, "drop: [ALL]"},
		{"oci", nil, "recommended-cap-add"},
		{"compose-patch", []string{"--compose-in", composeIn, "--service", "app"}, "@@"},
		{"compose-lint-profile", []string{"--allow-exploratory"}, "exploratory:"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			args := append([]string{"--cap-add", capaddGranted, "--format", tc.format}, tc.extra...)
			out, err := runCapadd(t, args...)
			if err != nil {
				t.Fatalf("run --format %s: %v", tc.format, err)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("--format %s output missing %q:\n%s", tc.format, tc.want, out)
			}
		})
	}

	// Default mode (no --cap-add): the advisory still emits, with no cap_add
	// block and no recommendation.
	out, err := runCapadd(t, "--format", "compose")
	if err != nil {
		t.Fatalf("default-mode compose: %v", err)
	}
	if strings.Contains(out, "cap_add:") {
		t.Errorf("default mode must not emit a cap_add block:\n%s", out)
	}
}

// TestRun_CapaddNegativePaths is TG5: the usage-error flag combinations and the
// default-mode contract gate.
func TestRun_CapaddNegativePaths(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"cap-add-without-capadd-observe", []string{"--fixture", capaddFixture, "--container", capaddFixtureContainer, "--cap-add", "SYS_ADMIN"}},
		{"compose-patch-without-compose-in", []string{"--fixture", capaddFixture, "--container", capaddFixtureContainer, "--observe", "capadd", "--cap-add", capaddGranted, "--format", "compose-patch", "--service", "app"}},
		{"compose-in-with-wrong-format", []string{"--fixture", capaddFixture, "--container", capaddFixtureContainer, "--observe", "capadd", "--format", "compose", "--compose-in", "/tmp/x.yaml"}},
		// Default mode (no --cap-add) cannot clear the compose-lint contract
		// (no granted set to contribute) without --allow-exploratory.
		{"compose-lint-profile-default-mode", []string{"--fixture", capaddFixture, "--container", capaddFixtureContainer, "--observe", "capadd", "--format", "compose-lint-profile"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			err := Run(tc.args, &out, &errBuf)
			if exit.CodeFor(err) != exit.Usage {
				t.Errorf("exit = %d, want exit.Usage (%d); err=%v", exit.CodeFor(err), exit.Usage, err)
			}
		})
	}
}

// TestCheckCapaddComposeLintContract is TG5: the contract gate's deterministic
// violation set across a clean sidecar and the failure modes.
func TestCheckCapaddComposeLintContract(t *testing.T) {
	dir := t.TempDir()
	workload := filepath.Join(dir, "w.sh")
	if err := os.WriteFile(workload, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	clean := func() *sidecar.Sidecar {
		s := sidecar.NewSidecar()
		s.ImageDigest = "img@sha256:" + strings.Repeat("a", 64)
		s.Workload = workload
		s.DurationSeconds = format.ComposeLintMinDurationSeconds
		s.Confidence.Level = sidecar.ConfidenceModerate
		s.CapaddValidation = &sidecar.CapaddValidation{GrantedSetProvided: true}
		return s
	}

	if v := format.CheckCapaddComposeLintContract(clean()); len(v) != 0 {
		t.Errorf("clean sidecar should clear the gate, got violations: %v", v)
	}

	// No granted set → the capadd-specific violation.
	s := clean()
	s.CapaddValidation.GrantedSetProvided = false
	if v := format.CheckCapaddComposeLintContract(s); !obstest.ContainsSubstr(v, "granted set not provided") {
		t.Errorf("missing granted-set violation: %v", v)
	}

	// Below-moderate confidence is a violation.
	s = clean()
	s.Confidence.Level = sidecar.ConfidenceLow
	if v := format.CheckCapaddComposeLintContract(s); !obstest.ContainsSubstr(v, "below moderate") {
		t.Errorf("missing confidence violation: %v", v)
	}

	// Missing image digest is a violation.
	s = clean()
	s.ImageDigest = ""
	if v := format.CheckCapaddComposeLintContract(s); !obstest.ContainsSubstr(v, "image_digest missing") {
		t.Errorf("missing image_digest violation: %v", v)
	}
}
