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

// TestAggregateCapadd_Filtering verifies the aggregator drops runc/init checks
// and non-active caps, excludes other containers, does not count denied
// (capable:false) checks as usage, and retains them separately (L10).
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

	// SYS_ADMIN: the runc:[2:INIT] execve check is filtered and the denied
	// (capable:false) perf_event_open check is not counted as usage, leaving only
	// the three held workload perf_event_open opens.
	sa := obs.Used["SYS_ADMIN"]
	if sa == nil {
		t.Fatal("SYS_ADMIN not observed")
	}
	if got := sa.syscalls["perf_event_open"]; got != 3 {
		t.Errorf("SYS_ADMIN perf_event_open held count = %d, want 3 (denied attempt excluded)", got)
	}
	if got := sa.events; got != 3 {
		t.Errorf("SYS_ADMIN held events = %d, want 3 (denied attempt not counted as usage)", got)
	}
	if _, ok := sa.syscalls["execve"]; ok {
		t.Error("runc:[2:INIT] execve check should have been filtered")
	}
	// L10: the denied perf_event_open attempt is retained separately, not dropped.
	if got := obs.Denied["SYS_ADMIN"]["perf_event_open"]; got != 1 {
		t.Errorf("denied SYS_ADMIN perf_event_open count = %d, want 1 (retained, not dropped)", got)
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
	advice, finer := capAdvice("SYS_ADMIN", []string{"perf_event_open"}, nil)
	if len(finer) != 1 || finer[0] != "PERFMON" {
		t.Errorf("SYS_ADMIN/perf finer = %v, want [PERFMON]", finer)
	}
	if !strings.Contains(advice, "PERFMON likely suffices") || !strings.Contains(advice, "perf_event_paranoid") {
		t.Errorf("advice = %q, want caveated PERFMON substitution", advice)
	}

	// SYS_ADMIN via bpf is NOT a clean substitution: CAP_BPF alone is unsound
	// (needs CAP_BPF + PERFMON/NET_ADMIN by program type), so `bpf` is unmapped
	// and the result falls through to base advice with no finer cap (M4).
	advice, finer = capAdvice("SYS_ADMIN", []string{"bpf"}, nil)
	if finer != nil {
		t.Errorf("SYS_ADMIN/bpf finer = %v, want nil (CAP_BPF alone is unsound)", finer)
	}
	if !strings.Contains(advice, "CAP_BPF alone") {
		t.Errorf("bpf advice = %q, want the CAP_BPF-alone caveat", advice)
	}

	// SYS_ADMIN via bpf + perf_event_open -> still no clean substitution (bpf
	// unmapped), so it falls through to base advice.
	_, finer = capAdvice("SYS_ADMIN", []string{"bpf", "perf_event_open"}, nil)
	if finer != nil {
		t.Errorf("SYS_ADMIN/bpf+perf finer = %v, want nil (bpf unmapped)", finer)
	}

	// SYS_ADMIN via perf_event_open AND mount -> no clean substitution (mount
	// has no finer cap), so it falls through to the base advice.
	advice, finer = capAdvice("SYS_ADMIN", []string{"mount", "perf_event_open"}, nil)
	if finer != nil {
		t.Errorf("mixed SYS_ADMIN finer = %v, want nil (no clean substitution)", finer)
	}
	if !strings.Contains(advice, "kitchen-sink") {
		t.Errorf("mixed advice = %q, want base advice", advice)
	}

	// L10: SYS_ADMIN held only via perf_event_open (a clean PERFMON candidate)
	// BUT with a denied (capable:false) mount attempt — mount has no finer cap,
	// so the substitution must be suppressed and the caveat must name the denied
	// broad attempt. The cap stays SYS_ADMIN, not PERFMON.
	advice, finer = capAdvice("SYS_ADMIN", []string{"perf_event_open"}, []string{"mount"})
	if finer != nil {
		t.Errorf("L10 SYS_ADMIN finer = %v, want nil (denied broad attempt suppresses substitution)", finer)
	}
	if !strings.Contains(advice, "denied") || !strings.Contains(advice, "mount") {
		t.Errorf("L10 advice = %q, want a denied-mount caveat", advice)
	}

	// L10 precision: a denied attempt for a FINER syscall (perf_event_open) does
	// NOT suppress the substitution — only denied broad (non-finer) syscalls do.
	advice, finer = capAdvice("SYS_ADMIN", []string{"perf_event_open"}, []string{"perf_event_open"})
	if len(finer) != 1 || finer[0] != "PERFMON" {
		t.Errorf("L10 finer-denied finer = %v, want [PERFMON] (finer denied attempt does not suppress)", finer)
	}
	if strings.Contains(advice, "denied") {
		t.Errorf("L10 finer-denied advice = %q, want no denied caveat", advice)
	}

	// NET_RAW: known, no finer cap. A denied broad attempt does not add a caveat
	// (there was no substitution to suppress; the cap is kept regardless).
	advice, finer = capAdvice("NET_RAW", []string{"socket"}, []string{"bind"})
	if finer != nil {
		t.Errorf("NET_RAW finer = %v, want nil", finer)
	}
	if !strings.Contains(advice, "ping_group_range") {
		t.Errorf("NET_RAW advice = %q, want ICMP note", advice)
	}
	if strings.Contains(advice, "denied") {
		t.Errorf("NET_RAW advice = %q, want no denied caveat (no substitution to suppress)", advice)
	}

	// Unknown cap: generic advice, no finer.
	advice, finer = capAdvice("FOOBAR", []string{"ioctl"}, nil)
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

// TestCapaddValidation_DeniedAttempts is the L10 regression: a denied
// (capable:false) broad-syscall attempt under a granted cap must not be silently
// discarded. It must (a) suppress a finer-grained substitution the held syscalls
// would otherwise justify, keeping the broad cap, and (b) keep a granted cap that
// was only ever attempted-and-denied out of the removable set.
func TestCapaddValidation_DeniedAttempts(t *testing.T) {
	// SYS_ADMIN: held via perf_event_open (a clean PERFMON candidate) but with a
	// denied mount — mount has no finer cap, so the substitution is unsafe.
	// SYS_MODULE: granted, never seen at all — a genuine removal candidate.
	// DAC_OVERRIDE: granted, only ever attempted-and-denied (openat) — wanted by
	// the workload under a grant it couldn't exercise; not removable.
	const fixture = `{"syscall":"perf_event_open","cap":"CAP_SYS_ADMIN","capable":true,"proc":{"comm":"app","pid":10},"runtime":{"containerId":"c1","containerImageName":"i:1"}}
{"syscall":"perf_event_open","cap":"CAP_SYS_ADMIN","capable":true,"proc":{"comm":"app","pid":10},"runtime":{"containerId":"c1","containerImageName":"i:1"}}
{"syscall":"mount","cap":"CAP_SYS_ADMIN","capable":false,"proc":{"comm":"app","pid":10},"runtime":{"containerId":"c1","containerImageName":"i:1"}}
{"syscall":"open_by_handle_at","cap":"CAP_DAC_OVERRIDE","capable":false,"proc":{"comm":"app","pid":11},"runtime":{"containerId":"c1","containerImageName":"i:1"}}
`
	active := parseCapSet("SYS_ADMIN,SYS_MODULE,DAC_OVERRIDE")
	obs, err := aggregateCapadd(strings.NewReader(fixture), aggregateOpts{Container: "c1"}, active)
	if err != nil {
		t.Fatalf("aggregateCapadd: %v", err)
	}
	v := capaddToValidation(obs, active, true)

	byCap := map[string]CapaddFinding{}
	for _, f := range v.Findings {
		byCap[f.Cap] = f
	}

	// SYS_ADMIN: used, substitution suppressed (no finer caps), denied caveat.
	sa := byCap["SYS_ADMIN"]
	if !sa.Used {
		t.Error("SYS_ADMIN should be Used (held perf_event_open)")
	}
	if len(sa.FinerCaps) != 0 {
		t.Errorf("SYS_ADMIN FinerCaps = %v, want empty (denied mount suppresses substitution)", sa.FinerCaps)
	}
	if !strings.Contains(sa.Advice, "denied") || !strings.Contains(sa.Advice, "mount") {
		t.Errorf("SYS_ADMIN advice = %q, want a denied-mount caveat", sa.Advice)
	}

	// SYS_MODULE: never observed at all -> genuine removal candidate.
	sm := byCap["SYS_MODULE"]
	if sm.Used || !sm.Removable {
		t.Errorf("SYS_MODULE = {Used:%v Removable:%v}, want unused+removable", sm.Used, sm.Removable)
	}

	// DAC_OVERRIDE: only denied attempts -> not used, NOT removable, caveated.
	do := byCap["DAC_OVERRIDE"]
	if do.Used {
		t.Error("DAC_OVERRIDE should not be Used (only denied attempts)")
	}
	if do.Removable {
		t.Error("DAC_OVERRIDE must NOT be removable (workload attempted it, was denied) — L10")
	}
	if !strings.Contains(do.Advice, "denied") {
		t.Errorf("DAC_OVERRIDE advice = %q, want a denied-attempt caveat", do.Advice)
	}

	// Recommendation keeps the two attempted caps, drops the genuinely-unused one,
	// and offers NO finer substitute (PERFMON) for the suppressed SYS_ADMIN.
	want := []string{"DAC_OVERRIDE", "SYS_ADMIN"}
	if strings.Join(v.RecommendedCapAdd, ",") != strings.Join(want, ",") {
		t.Errorf("RecommendedCapAdd = %v, want %v", v.RecommendedCapAdd, want)
	}
	for _, c := range v.RecommendedCapAdd {
		if c == "PERFMON" {
			t.Error("RecommendedCapAdd contains PERFMON; substitution should have been suppressed (L10)")
		}
		if c == "SYS_MODULE" {
			t.Error("RecommendedCapAdd contains SYS_MODULE; the genuinely-unused cap should be dropped")
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
