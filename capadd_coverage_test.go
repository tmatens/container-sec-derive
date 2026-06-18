package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// This file closes the v0.4 capadd test gaps the #120 deep review flagged
// (TG1–TG5): the run()-level CLI was 0% covered, computeCapaddConfidence had no
// dedicated test, the live observeCapadd/observeDevices paths were 0%, and
// multi-replica + negative/contract paths were untested.

const capaddFixture = "testdata/capadd/sample.ndjson"
const capaddFixtureContainer = "aabbccddeeff0011"

// runCapadd drives run() against the capadd fixture with the given extra args
// and returns stdout + the run error.
func runCapadd(t *testing.T, extra ...string) (string, error) {
	t.Helper()
	args := append([]string{
		"--fixture", capaddFixture,
		"--container", capaddFixtureContainer,
		"--observe", "capadd",
	}, extra...)
	var out, errBuf bytes.Buffer
	err := run(args, &out, &errBuf)
	return out.String(), err
}

// TestRun_CapaddAllFormats is TG1: produceCapaddObservation + every formatter
// driven end-to-end through run(), in granted mode (--cap-add). Each format must
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

// TestComputeCapaddConfidence is TG2: the rubric's grade + factors across the
// states that drive it, including the L9 substitution-pricing regression.
func TestComputeCapaddConfidence(t *testing.T) {
	mk := func(mut func(s *sidecar.Sidecar)) *sidecar.Sidecar {
		s := sidecar.NewSidecar()
		s.CapaddValidation = &sidecar.CapaddValidation{GrantedSetProvided: true}
		mut(s)
		computeCapaddConfidence(s)
		return s
	}

	// Clean: a used cap, workload provided, no drops/disagreement → moderate
	// (the deferred factors cap the grade at moderate).
	s := mk(func(s *sidecar.Sidecar) {
		s.CapaddValidation.Findings = []sidecar.CapaddFinding{{Cap: "NET_RAW", Used: true}}
		s.Workload = "/w.sh"
	})
	if s.Confidence.Level != sidecar.ConfidenceModerate {
		t.Errorf("clean: level = %q, want moderate (%v)", s.Confidence.Level, s.Confidence.Factors)
	}

	// No workload + a small (<1%) drop rate = two moderate factors → low.
	s = mk(func(s *sidecar.Sidecar) {
		s.CapaddValidation.Findings = []sidecar.CapaddFinding{{Cap: "NET_RAW", Used: true}}
		s.TraceHealth.DropRate = 0.005
	})
	if s.Confidence.Level != sidecar.ConfidenceLow {
		t.Errorf("no-workload+small-drop: level = %q, want low (%v)", s.Confidence.Level, s.Confidence.Factors)
	}

	// Drop rate >= 1% forces low on its own.
	s = mk(func(s *sidecar.Sidecar) {
		s.Workload = "/w.sh"
		s.TraceHealth.DropRate = 0.02
	})
	if s.Confidence.Level != sidecar.ConfidenceLow {
		t.Errorf("high-drop: level = %q, want low", s.Confidence.Level)
	}

	// L9 regression: a finer-cap substitution is priced — it appears as a
	// workload-bounded factor (not silently ignored). With a workload present it
	// stays moderate, but the substitution factor must be surfaced.
	s = mk(func(s *sidecar.Sidecar) {
		s.CapaddValidation.Findings = []sidecar.CapaddFinding{{Cap: "SYS_ADMIN", Used: true, FinerCaps: []string{"PERFMON"}}}
		s.Workload = "/w.sh"
	})
	if !containsSubstr(s.Confidence.Factors, "substitution") {
		t.Errorf("substitution not priced in factors: %v", s.Confidence.Factors)
	}

	// Substitution without a workload names the substitution caveat and is a
	// moderate factor (one moderate alone stays moderate).
	s = mk(func(s *sidecar.Sidecar) {
		s.CapaddValidation.Findings = []sidecar.CapaddFinding{{Cap: "SYS_ADMIN", Used: true, FinerCaps: []string{"PERFMON"}}}
	})
	if !containsSubstr(s.Confidence.Factors, "substitution") {
		t.Errorf("no-workload substitution caveat missing: %v", s.Confidence.Factors)
	}
}

// TestObserveCapadd_FakeIG is TG3: the live spawn → parse → drop-accounting path
// for the capadd observer, exercised with a fake ig that streams
// trace_capabilities events and a "lost N samples" stderr line.
func TestObserveCapadd_FakeIG(t *testing.T) {
	nd := strings.Join([]string{
		`{"syscall":"perf_event_open","cap":"CAP_SYS_ADMIN","capable":true,"proc":{"comm":"app"},"runtime":{"containerId":"c1","containerName":"web","containerImageName":"web:1"}}`,
		`{"syscall":"ptrace","cap":"CAP_SYS_PTRACE","capable":true,"proc":{"comm":"app"},"runtime":{"containerId":"c1","containerName":"web","containerImageName":"web:1"}}`,
		`{"syscall":"chown","cap":"CAP_CHOWN","capable":true,"proc":{"comm":"app"},"runtime":{"containerId":"c1","containerName":"web","containerImageName":"web:1"}}`,
	}, "\n")
	ig := fakeIGRun(t, nd, "level=info msg=starting\nlost 4 samples\n")

	obs, err := observeCapadd(context.Background(), ig, attrib.Opts{}, dangerousCaps, io.Discard)
	if err != nil {
		t.Fatalf("observeCapadd: %v", err)
	}
	// SYS_ADMIN + SYS_PTRACE are in the dangerous set; CHOWN is routine and
	// excluded, so EventCount is 2.
	if obs.EventCount != 2 {
		t.Errorf("EventCount = %d, want 2 (CHOWN is not a dangerous cap)", obs.EventCount)
	}
	if obs.Used["SYS_ADMIN"] == nil || obs.Used["SYS_PTRACE"] == nil {
		t.Errorf("expected SYS_ADMIN + SYS_PTRACE observed, got %v", obs.Used)
	}
	if obs.Dropped != 4 {
		t.Errorf("Dropped = %d, want 4 (from 'lost 4 samples')", obs.Dropped)
	}
}

// TestObserveCapadd_IGMissing is TG3: a missing ig binary maps to exit.IGMissing.
func TestObserveCapadd_IGMissing(t *testing.T) {
	_, err := observeCapadd(context.Background(), "/nonexistent/csd-ig-capadd-test", attrib.Opts{}, dangerousCaps, io.Discard)
	if exit.CodeFor(err) != exit.IGMissing {
		t.Errorf("exit = %d, want exit.IGMissing (%d); err=%v", exit.CodeFor(err), exit.IGMissing, err)
	}
}

// TestObserveDevices_FakeIG is TG3 for the device observer's live path (also 0%
// before): a fake ig streams trace_open device events + a loss line.
func TestObserveDevices_FakeIG(t *testing.T) {
	nd := strings.Join([]string{
		`{"syscall":"openat","flags_raw":2,"fpath":"/dev/kvm","proc":{"comm":"q"},"runtime":{"containerId":"c1","containerName":"vm","containerImageName":"vm:1"}}`,
		`{"syscall":"openat","flags_raw":2,"fpath":"/dev/null","proc":{"comm":"q"},"runtime":{"containerId":"c1","containerName":"vm","containerImageName":"vm:1"}}`,
	}, "\n")
	ig := fakeIGRun(t, nd, "lost 2 samples\n")

	obs, err := observeDevices(context.Background(), ig, attrib.Opts{}, io.Discard)
	if err != nil {
		t.Fatalf("observeDevices: %v", err)
	}
	// /dev/null is a default device node (excluded); /dev/kvm is a real grant.
	if len(obs.Devices) != 1 || obs.Devices[0] != "/dev/kvm" {
		t.Errorf("Devices = %v, want [/dev/kvm]", obs.Devices)
	}
	if obs.Dropped != 2 {
		t.Errorf("Dropped = %d, want 2", obs.Dropped)
	}
}

// TestCapaddMultiReplica is TG4: under --all-matching a cap observed on only one
// of two replicas surfaces in ReplicaCapDisagreement, and an --image matching >1
// replica without --all-matching is refused as ambiguous.
func TestCapaddMultiReplica(t *testing.T) {
	// Both replicas hit SYS_ADMIN; only repl-2 hits SYS_PTRACE.
	nd := strings.Join([]string{
		`{"syscall":"perf_event_open","cap":"CAP_SYS_ADMIN","capable":true,"proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"r1","containerImageName":"img:1"}}`,
		`{"syscall":"perf_event_open","cap":"CAP_SYS_ADMIN","capable":true,"proc":{"comm":"app"},"runtime":{"containerId":"bbb222bbb222","containerName":"r2","containerImageName":"img:1"}}`,
		`{"syscall":"ptrace","cap":"CAP_SYS_PTRACE","capable":true,"proc":{"comm":"app"},"runtime":{"containerId":"bbb222bbb222","containerName":"r2","containerImageName":"img:1"}}`,
	}, "\n")

	// --all-matching aggregates and records the disagreement.
	opts := attrib.Opts{Image: "img:1", AllMatching: true}
	obs, err := aggregateCapadd(strings.NewReader(nd), opts, dangerousCaps)
	if err != nil {
		t.Fatalf("aggregateCapadd: %v", err)
	}
	s := capaddToSidecar(obs, capaddPipelineOpts{AggregateOpts: opts, ActiveSet: dangerousCaps})
	if !equalSlice(s.Target.ReplicaCapDisagreement, []string{"SYS_PTRACE"}) {
		t.Errorf("ReplicaCapDisagreement = %v, want [SYS_PTRACE]", s.Target.ReplicaCapDisagreement)
	}

	// --image matching >1 replica without --all-matching is ambiguous.
	_, err = aggregateCapadd(strings.NewReader(nd), attrib.Opts{Image: "img:1"}, dangerousCaps)
	var amb *exit.AmbiguousSelectionError
	if err == nil || !errors.As(err, &amb) {
		t.Fatalf("err = %v, want *exit.AmbiguousSelectionError", err)
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
			err := run(tc.args, &out, &errBuf)
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
		s.DurationSeconds = ComposeLintMinDurationSeconds
		s.Confidence.Level = sidecar.ConfidenceModerate
		s.CapaddValidation = &sidecar.CapaddValidation{GrantedSetProvided: true}
		return s
	}

	if v := checkCapaddComposeLintContract(clean()); len(v) != 0 {
		t.Errorf("clean sidecar should clear the gate, got violations: %v", v)
	}

	// No granted set → the capadd-specific violation.
	s := clean()
	s.CapaddValidation.GrantedSetProvided = false
	if v := checkCapaddComposeLintContract(s); !containsSubstr(v, "granted set not provided") {
		t.Errorf("missing granted-set violation: %v", v)
	}

	// Below-moderate confidence is a violation.
	s = clean()
	s.Confidence.Level = sidecar.ConfidenceLow
	if v := checkCapaddComposeLintContract(s); !containsSubstr(v, "below moderate") {
		t.Errorf("missing confidence violation: %v", v)
	}

	// Missing image digest is a violation.
	s = clean()
	s.ImageDigest = ""
	if v := checkCapaddComposeLintContract(s); !containsSubstr(v, "image_digest missing") {
		t.Errorf("missing image_digest violation: %v", v)
	}
}
