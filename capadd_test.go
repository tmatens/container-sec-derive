package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// capaddGranted is the validate-set the fixture-driven tests use: a granted set
// exercising every branch — a finer substitution (SYS_ADMIN -> PERFMON), a
// no-finer used cap (NET_RAW, SYS_PTRACE), and an unused/removable cap
// (SYS_MODULE, never observed).
const capaddGranted = "SYS_ADMIN,NET_RAW,SYS_MODULE,SYS_PTRACE"

func capaddSidecarFromFixture(t *testing.T, granted string, hasGranted bool) *Sidecar {
	t.Helper()
	f, err := os.Open("testdata/capadd/sample.ndjson")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	set := parseCapSet(granted)
	active := set
	if active == nil {
		active = dangerousCaps
	}
	obs, err := aggregateCapadd(f, aggregateOpts{Container: "aabbccddeeff0011"}, active)
	if err != nil {
		t.Fatalf("aggregateCapadd: %v", err)
	}
	s := capaddToSidecar(obs, capaddPipelineOpts{
		AggregateOpts: aggregateOpts{Container: "aabbccddeeff0011"},
		ActiveSet:     active,
		Granted:       hasGranted,
	})
	s.ObservedAt = time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	s.DurationSeconds = 600
	computeCapaddConfidence(s)
	return s
}

// TestCapadd_Golden pins the v0.5 capadd_validation JSON shape — the additive
// block alongside the empty cap/fs/device scaffolding — against
// testdata/capadd_golden.json. Same harness as TestSidecar_GoldenPostgres1; run
// with -update-golden to refresh after an intentional schema change.
func TestCapadd_Golden(t *testing.T) {
	s := capaddSidecarFromFixture(t, capaddGranted, true)

	got, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "capadd_golden.json")
	if *updateGolden {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s (%d bytes)", goldenPath, len(got))
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update-golden to create)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch. Diff:\n--- want\n%s\n--- got\n%s", want, got)
	}
}

// TestAggregateCapadd_Filtering verifies the aggregator drops runc/init checks,
// denied (capable:false) checks, non-active caps, and other containers' events.
func TestAggregateCapadd_Filtering(t *testing.T) {
	f, err := os.Open("testdata/capadd/sample.ndjson")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	granted := parseCapSet(capaddGranted)
	obs, err := aggregateCapadd(f, aggregateOpts{Container: "aabbccddeeff0011"}, granted)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}

	// SYS_ADMIN: the runc:[2:INIT] execve check and the denied mount check are
	// both filtered, leaving only the three workload perf_event_open opens.
	sa := obs.Used["SYS_ADMIN"]
	if sa == nil {
		t.Fatal("SYS_ADMIN not observed")
	}
	if got := sa.syscalls["perf_event_open"]; got != 3 {
		t.Errorf("SYS_ADMIN perf_event_open count = %d, want 3", got)
	}
	if _, ok := sa.syscalls["execve"]; ok {
		t.Error("runc:[2:INIT] execve check should have been filtered")
	}
	if _, ok := sa.syscalls["mount"]; ok {
		t.Error("denied (capable:false) mount check should have been filtered")
	}
	// CHOWN is non-dangerous and not in the granted set; never recorded.
	if _, ok := obs.Used["CHOWN"]; ok {
		t.Error("CHOWN is outside the validate-set; should not be recorded")
	}
	// The unrelated container's NET_RAW must not leak into this target.
	if obs.Used["NET_RAW"].events != 2 {
		t.Errorf("NET_RAW events = %d, want 2 (other container excluded)", obs.Used["NET_RAW"].events)
	}
	// EventCount is the held, in-set, post-filter total: perf*3 + socket*2 +
	// ptrace + process_vm_readv = 7.
	if obs.EventCount != 7 {
		t.Errorf("EventCount = %d, want 7", obs.EventCount)
	}
}

// TestCapAdvice covers the knowledge-base substitution logic: a clean finer
// substitution, a mixed-syscall case with no clean substitution, a no-finer
// known cap, and an unknown cap's generic advice.
func TestCapAdvice(t *testing.T) {
	// SYS_ADMIN observed only via perf_event_open -> PERFMON (a softened,
	// caveated substitution — not a flat "is sufficient"; deep-review M4).
	advice, finer := capAdvice("SYS_ADMIN", []string{"perf_event_open"})
	if len(finer) != 1 || finer[0] != "PERFMON" {
		t.Errorf("SYS_ADMIN/perf finer = %v, want [PERFMON]", finer)
	}
	if !strings.Contains(advice, "PERFMON likely suffices") || !strings.Contains(advice, "perf_event_paranoid") {
		t.Errorf("advice = %q, want caveated PERFMON substitution", advice)
	}

	// SYS_ADMIN via bpf is NOT a clean substitution: CAP_BPF alone is unsound
	// (needs CAP_BPF + PERFMON/NET_ADMIN by program type), so `bpf` is unmapped
	// and the result falls through to base advice with no finer cap (M4).
	advice, finer = capAdvice("SYS_ADMIN", []string{"bpf"})
	if finer != nil {
		t.Errorf("SYS_ADMIN/bpf finer = %v, want nil (CAP_BPF alone is unsound)", finer)
	}
	if !strings.Contains(advice, "CAP_BPF alone") {
		t.Errorf("bpf advice = %q, want the CAP_BPF-alone caveat", advice)
	}

	// SYS_ADMIN via bpf + perf_event_open -> still no clean substitution (bpf
	// unmapped), so it falls through to base advice.
	_, finer = capAdvice("SYS_ADMIN", []string{"bpf", "perf_event_open"})
	if finer != nil {
		t.Errorf("SYS_ADMIN/bpf+perf finer = %v, want nil (bpf unmapped)", finer)
	}

	// SYS_ADMIN via perf_event_open AND mount -> no clean substitution (mount
	// has no finer cap), so it falls through to the base advice.
	advice, finer = capAdvice("SYS_ADMIN", []string{"mount", "perf_event_open"})
	if finer != nil {
		t.Errorf("mixed SYS_ADMIN finer = %v, want nil (no clean substitution)", finer)
	}
	if !strings.Contains(advice, "kitchen-sink") {
		t.Errorf("mixed advice = %q, want base advice", advice)
	}

	// NET_RAW: known, no finer cap.
	advice, finer = capAdvice("NET_RAW", []string{"socket"})
	if finer != nil {
		t.Errorf("NET_RAW finer = %v, want nil", finer)
	}
	if !strings.Contains(advice, "ping_group_range") {
		t.Errorf("NET_RAW advice = %q, want ICMP note", advice)
	}

	// Unknown cap: generic advice, no finer.
	advice, finer = capAdvice("FOOBAR", []string{"ioctl"})
	if finer != nil || !strings.Contains(advice, "review whether") {
		t.Errorf("unknown cap advice = %q finer = %v", advice, finer)
	}
}

// TestCapaddValidation_GrantedVsDefault checks the two report modes: with a
// granted set every cap appears (used or removable) and a recommendation is
// synthesized; without one, only observed dangerous caps appear and no
// recommendation is produced.
func TestCapaddValidation_GrantedVsDefault(t *testing.T) {
	// Granted mode.
	s := capaddSidecarFromFixture(t, capaddGranted, true)
	v := s.CapaddValidation
	if !v.GrantedSetProvided {
		t.Fatal("GrantedSetProvided = false, want true")
	}
	want := []string{"NET_RAW", "PERFMON", "SYS_PTRACE"}
	if strings.Join(v.RecommendedCapAdd, ",") != strings.Join(want, ",") {
		t.Errorf("RecommendedCapAdd = %v, want %v", v.RecommendedCapAdd, want)
	}
	var removable []string
	for _, f := range v.Findings {
		if f.Removable {
			removable = append(removable, f.Cap)
		}
	}
	if len(removable) != 1 || removable[0] != "SYS_MODULE" {
		t.Errorf("removable = %v, want [SYS_MODULE]", removable)
	}

	// Default mode (no --cap-add): only the dangerous caps observed in use.
	s = capaddSidecarFromFixture(t, "", false)
	v = s.CapaddValidation
	if v.GrantedSetProvided {
		t.Error("GrantedSetProvided = true, want false in default mode")
	}
	if len(v.RecommendedCapAdd) != 0 {
		t.Errorf("default-mode RecommendedCapAdd = %v, want empty", v.RecommendedCapAdd)
	}
	for _, f := range v.Findings {
		if !f.Used {
			t.Errorf("default mode emitted a non-used finding for %s", f.Cap)
		}
	}
	// SYS_ADMIN, NET_RAW, SYS_PTRACE are observed dangerous caps; SYS_MODULE
	// (unused) must not appear without an explicit granted set.
	for _, f := range v.Findings {
		if f.Cap == "SYS_MODULE" {
			t.Error("default mode should not report unused SYS_MODULE")
		}
	}
}

// TestCapaddCompose_GrantedEmitsCapAdd checks the compose formatter emits the
// advisory comments plus a minimized cap_add when a granted set was supplied, and
// the advisory alone otherwise.
func TestCapaddCompose(t *testing.T) {
	s := capaddSidecarFromFixture(t, capaddGranted, true)
	var buf bytes.Buffer
	if err := writeCapaddCompose(&buf, s.CapaddValidation); err != nil {
		t.Fatalf("writeCapaddCompose: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# csd dangerous cap_add validation",
		"# SYS_ADMIN: observed only via perf_event_open; PERFMON likely suffices",
		"# dropped (unused under this workload): SYS_MODULE",
		"cap_add:",
		"  - PERFMON",
		"  - SYS_PTRACE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compose output missing %q:\n%s", want, out)
		}
	}

	// Default mode: advisory only, no cap_add block.
	s = capaddSidecarFromFixture(t, "", false)
	buf.Reset()
	if err := writeCapaddCompose(&buf, s.CapaddValidation); err != nil {
		t.Fatalf("writeCapaddCompose default: %v", err)
	}
	if strings.Contains(buf.String(), "cap_add:") {
		t.Errorf("default mode should not emit cap_add block:\n%s", buf.String())
	}
}

// TestCapaddFormatters_Smoke exercises the remaining text formatters for basic
// validity (no error, key content present) in granted mode.
func TestCapaddFormatters_Smoke(t *testing.T) {
	s := capaddSidecarFromFixture(t, capaddGranted, true)
	val := s.CapaddValidation

	var buf bytes.Buffer
	if err := writeCapaddDockerRun(&buf, val); err != nil {
		t.Fatalf("docker-run: %v", err)
	}
	if !strings.Contains(buf.String(), "--cap-add PERFMON") {
		t.Errorf("docker-run missing --cap-add PERFMON:\n%s", buf.String())
	}

	buf.Reset()
	if err := writeCapaddK8s(&buf, val); err != nil {
		t.Fatalf("k8s: %v", err)
	}
	if !strings.Contains(buf.String(), "drop: [ALL]") || !strings.Contains(buf.String(), "PERFMON") {
		t.Errorf("k8s output unexpected:\n%s", buf.String())
	}

	buf.Reset()
	if err := writeCapaddOCI(&buf, val); err != nil {
		t.Fatalf("oci: %v", err)
	}
	var oci struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(buf.Bytes(), &oci); err != nil {
		t.Fatalf("oci not valid JSON: %v\n%s", err, buf.String())
	}
	if oci.Annotations["org.containersecderive.recommended-cap-add"] != "NET_RAW,PERFMON,SYS_PTRACE" {
		t.Errorf("oci recommended-cap-add = %q", oci.Annotations["org.containersecderive.recommended-cap-add"])
	}
}

// TestCapaddComposePatch rewrites a service's cap_add to the recommended set.
func TestCapaddComposePatch(t *testing.T) {
	s := capaddSidecarFromFixture(t, capaddGranted, true)
	compose := []byte("services:\n  app:\n    image: myapp:1\n    cap_add:\n      - SYS_ADMIN\n      - NET_RAW\n      - SYS_MODULE\n      - SYS_PTRACE\n")
	var buf bytes.Buffer
	if err := writeCapaddComposePatch(&buf, s.CapaddValidation, compose, "compose.yml", "app"); err != nil {
		t.Fatalf("compose-patch: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "-      - SYS_ADMIN") && !strings.Contains(out, "-      - SYS_MODULE") {
		t.Errorf("patch should remove SYS_ADMIN/SYS_MODULE lines:\n%s", out)
	}
	if !strings.Contains(out, "+      - PERFMON") {
		t.Errorf("patch should add PERFMON:\n%s", out)
	}

	// Default mode proposes no change.
	s = capaddSidecarFromFixture(t, "", false)
	buf.Reset()
	if err := writeCapaddComposePatch(&buf, s.CapaddValidation, compose, "compose.yml", "app"); err != nil {
		t.Fatalf("compose-patch default: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("default mode should propose no patch, got:\n%s", buf.String())
	}
}

// TestCapaddProfile_ContractGate checks the compose-lint-profile contract:
// without a granted set it is a violation (no minimized cap_add to contribute),
// and --allow-exploratory emits under exploratory:.
func TestCapaddProfile_ContractGate(t *testing.T) {
	s := capaddSidecarFromFixture(t, "", false)
	var buf bytes.Buffer
	err := writeCapaddComposeLintProfile(&buf, s, false)
	if err == nil {
		t.Fatal("expected contract violation without a granted set")
	}
	if !strings.Contains(err.Error(), "granted set not provided") {
		t.Errorf("violation = %v, want granted-set mention", err)
	}

	// allow-exploratory emits anyway, under exploratory:.
	buf.Reset()
	if err := writeCapaddComposeLintProfile(&buf, s, true); err != nil {
		t.Fatalf("exploratory emit: %v", err)
	}
	if !strings.Contains(buf.String(), "exploratory:") {
		t.Errorf("exploratory output missing wrapper:\n%s", buf.String())
	}
}
