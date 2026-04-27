package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ev builds an ig v0.51.0 trace_capabilities line. Tests use this
// helper rather than inline JSON so a future schema bump touches one
// function instead of every assertion. Fields not named default to
// empty; tests pass only what each assertion actually cares about.
func ev(fields ...string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(fields); i += 2 {
		m[fields[i]] = fields[i+1]
	}
	if m["containerId"] == "" && m["containerName"] != "" {
		m["containerId"] = m["containerName"]
	}
	ts := m["timestamp"]
	if ts == "" {
		ts = "0"
	}
	// capable defaults to true (held). Pass capable=false to model a
	// kretprobe-recorded denial that the Step 19 filter must drop.
	capable := "true"
	if v, ok := m["capable"]; ok {
		capable = v
	}
	return `{"timestamp":` + ts +
		`,"cap":"` + m["cap"] + `"` +
		`,"capable":` + capable +
		`,"proc":{"comm":"` + m["comm"] + `","pid":0}` +
		`,"runtime":{"runtimeName":"docker","containerId":"` + m["containerId"] +
		`","containerName":"` + m["containerName"] +
		`","containerImageName":"` + m["image"] + `"}}` + "\n"
}

func TestAggregate_DistinctCapsSorted(t *testing.T) {
	input := ev("cap", "CAP_CHOWN", "containerId", "abc123def456", "containerName", "pg") +
		ev("cap", "CAP_SETUID", "containerId", "abc123def456", "containerName", "pg") +
		ev("cap", "CAP_CHOWN", "containerId", "abc123def456", "containerName", "pg") +
		ev("cap", "CAP_DAC_OVERRIDE", "containerId", "abc123def456", "containerName", "pg")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "pg"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	want := []string{"CHOWN", "DAC_OVERRIDE", "SETUID"}
	if !equalSlice(s.CapNames(), want) {
		t.Errorf("caps = %v, want %v", s.CapNames(), want)
	}
}

func TestAggregate_FiltersByContainer(t *testing.T) {
	input := ev("cap", "CAP_CHOWN", "containerId", "aaa", "containerName", "pg") +
		ev("cap", "CAP_NET_RAW", "containerId", "bbb", "containerName", "other")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "pg"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN"}) {
		t.Errorf("expected only CHOWN for pg, got %v", s.CapNames())
	}
}

func TestAggregate_ContainerIDPrefix(t *testing.T) {
	input := ev("cap", "CAP_SETGID", "containerId", "abcdef1234567890")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "abcdef"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"SETGID"}) {
		t.Errorf("prefix match failed, got %v", s.CapNames())
	}
}

func TestAggregate_EmptyTargetMatchesAll(t *testing.T) {
	input := ev("cap", "CAP_CHOWN", "containerId", "a") +
		ev("cap", "CAP_SETUID", "containerId", "b")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN", "SETUID"}) {
		t.Errorf("got %v", s.CapNames())
	}
}

func TestAggregate_FiltersCapableFalse(t *testing.T) {
	// PLAN.md §IG vs Tracee: ig's kretprobe records both held and
	// denied checks. The derived cap set must include only held caps;
	// denied checks (capable=false) are kernel "no" answers and would
	// inflate the profile if counted.
	input := ev("timestamp", "1000", "cap", "CAP_CHOWN", "containerId", "a", "capable", "true") +
		ev("timestamp", "1001", "cap", "CAP_NET_RAW", "containerId", "a", "capable", "false") +
		ev("timestamp", "1002", "cap", "CAP_SYS_ADMIN", "containerId", "a", "capable", "false") +
		ev("timestamp", "1003", "cap", "CAP_SETUID", "containerId", "a", "capable", "true")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN", "SETUID"}) {
		t.Errorf("denied caps leaked into derived set: got %v, want only held caps", s.CapNames())
	}
	// Denials still count toward events_recorded so drop_rate's
	// denominator reflects every real ig sample we parsed.
	if s.TraceHealth.EventsRecorded != 4 {
		t.Errorf("EventsRecorded = %d, want 4 (denials must count toward drop-rate denominator)", s.TraceHealth.EventsRecorded)
	}
}

func TestAggregate_LegacyFixtureWithoutCapableFieldKeptForCompat(t *testing.T) {
	// Hand-rolled fixtures predating Step 19 omit the capable field.
	// UnmarshalJSON treats absent as true so they don't silently drop
	// to zero caps; pinned ig v0.51.0 always emits the field, so the
	// live path still gets exact verdict semantics.
	input := `{"timestamp":1000,"cap":"CAP_CHOWN","proc":{"comm":"x","pid":1},"runtime":{"runtimeName":"docker","containerId":"a","containerName":"a","containerImageName":"x"}}` + "\n"
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN"}) {
		t.Errorf("legacy fixture got filtered (absent capable should default to true): %v", s.CapNames())
	}
}

func TestAggregate_SkipsMalformedLines(t *testing.T) {
	input := "not json at all\n" +
		ev("cap", "CAP_CHOWN", "containerId", "a") +
		"\n" + // blank line
		ev("cap", "CAP_SETUID", "containerId", "a")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN", "SETUID"}) {
		t.Errorf("got %v", s.CapNames())
	}
}

func TestAggregate_InitWindowFiltersEarlyEvents(t *testing.T) {
	// First event sets t=0; a 500ms window must drop anything before 500ms
	// and keep anything at/after it.
	input := ev("timestamp", "1000", "cap", "CAP_SYS_ADMIN", "containerId", "a") +
		ev("timestamp", "1100", "cap", "CAP_DAC_READ_SEARCH", "containerId", "a") +
		ev("timestamp", "1600", "cap", "CAP_CHOWN", "containerId", "a") +
		ev("timestamp", "1700", "cap", "CAP_SETUID", "containerId", "a")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a", InitWindowMs: 500})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN", "SETUID"}) {
		t.Errorf("expected init-phase caps suppressed, got %v", s.CapNames())
	}
	if s.Target.InitWindowSuppressed != 2 {
		t.Errorf("InitWindowSuppressed = %d, want 2", s.Target.InitWindowSuppressed)
	}
}

func TestAggregate_InitWindowDisabled(t *testing.T) {
	input := ev("timestamp", "1000", "cap", "CAP_SYS_ADMIN", "containerId", "a") +
		ev("timestamp", "1600", "cap", "CAP_CHOWN", "containerId", "a")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN", "SYS_ADMIN"}) {
		t.Errorf("window=0 should keep all events, got %v", s.CapNames())
	}
	if s.Target.InitWindowSuppressed != 0 {
		t.Errorf("InitWindowSuppressed = %d, want 0", s.Target.InitWindowSuppressed)
	}
}

func TestAggregate_InitCommFilterDropsRuncEvents(t *testing.T) {
	// PLAN.md §Foot-guns: runc:[*] events are init-process capability
	// checks, not workload behavior. Step 11.1 follow-up (iii) saw
	// runc:[2:INIT] events leak past the 500ms time window; the comm
	// filter must drop them regardless of when they fire.
	input := ev("timestamp", "1000", "cap", "CAP_SYS_ADMIN", "comm", "runc:[2:INIT]", "containerId", "a") +
		ev("timestamp", "1600", "cap", "CAP_NET_ADMIN", "comm", "runc:[2:INIT]", "containerId", "a") + // past time window, still runc
		ev("timestamp", "1700", "cap", "CAP_CHOWN", "comm", "postgres", "containerId", "a") +
		ev("timestamp", "1800", "cap", "CAP_SETUID", "comm", "postgres", "containerId", "a")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a", InitWindowMs: 500})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN", "SETUID"}) {
		t.Errorf("expected runc events suppressed by comm, got %v", s.CapNames())
	}
	if s.Target.InitWindowSuppressed != 2 {
		t.Errorf("InitWindowSuppressed = %d, want 2 (both runc events)", s.Target.InitWindowSuppressed)
	}
}

func TestAggregate_InitCommFilterFiresWithoutTimeWindow(t *testing.T) {
	// Comm filter is independent of --init-window-ms: even with the time
	// window disabled, runc:[*] events must still be dropped.
	input := ev("timestamp", "1000", "cap", "CAP_SYS_ADMIN", "comm", "runc:[2:INIT]", "containerId", "a") +
		ev("timestamp", "1100", "cap", "CAP_CHOWN", "comm", "postgres", "containerId", "a")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN"}) {
		t.Errorf("comm filter should fire even with time window disabled, got %v", s.CapNames())
	}
	if s.Target.InitWindowSuppressed != 1 {
		t.Errorf("InitWindowSuppressed = %d, want 1 (the runc event)", s.Target.InitWindowSuppressed)
	}
}

func TestAggregate_InitCommFilterDoesNotFilterUnrelatedComms(t *testing.T) {
	// "runc-something" without the colon must not match (only runc:[*]
	// is the documented init shape; conservative prefix avoids
	// accidentally filtering user processes named e.g. "runcounter").
	input := ev("timestamp", "1000", "cap", "CAP_CHOWN", "comm", "runcounter", "containerId", "a") +
		ev("timestamp", "1100", "cap", "CAP_SETUID", "comm", "runc-helper", "containerId", "a")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN", "SETUID"}) {
		t.Errorf("non-runc-init comms should not be filtered, got %v", s.CapNames())
	}
}

func TestAggregate_InitWindowIgnoresUnmatchedEvents(t *testing.T) {
	// Events for other containers must not anchor the init window for
	// the target. First *matching* event is the reference point.
	input := ev("timestamp", "1000", "cap", "CAP_NET_RAW", "containerId", "other") +
		ev("timestamp", "5000", "cap", "CAP_SYS_ADMIN", "containerId", "a") +
		ev("timestamp", "5600", "cap", "CAP_CHOWN", "containerId", "a")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a", InitWindowMs: 500})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN"}) {
		t.Errorf("expected only CHOWN (SYS_ADMIN anchors+drops), got %v", s.CapNames())
	}
	if s.Target.InitWindowSuppressed != 1 {
		t.Errorf("InitWindowSuppressed = %d, want 1", s.Target.InitWindowSuppressed)
	}
}

func TestRun_FixtureMode(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "postgres-1"}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	// Expected caps from the sample fixture, matching compose-lint's
	// curated postgres profile (PLAN.md §v1 success criteria). Default
	// stdout format is compose (PLAN.md §Decisions item 2).
	want := "cap_drop:\n  - ALL\ncap_add:\n  - CHOWN\n  - DAC_OVERRIDE\n  - FOWNER\n  - SETGID\n  - SETUID\n"
	if out.String() != want {
		t.Errorf("output mismatch:\ngot:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestAggregate_EventsRecordedCountsParsedEvents(t *testing.T) {
	// Step 11 found ig v0.51.0 does not emit a typed trace_health stdout
	// event; events_recorded is now the aggregator's own count of
	// successfully parsed + matching cap events (pre-init-filter).
	input := ev("timestamp", "1000", "cap", "CAP_CHOWN", "containerId", "a") +
		ev("timestamp", "1100", "cap", "CAP_CHOWN", "containerId", "a") +
		ev("timestamp", "1600", "cap", "CAP_SETUID", "containerId", "a")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a", InitWindowMs: 500})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if s.TraceHealth.EventsRecorded != 3 {
		t.Errorf("EventsRecorded = %d, want 3 (two pre-init-filter + one post)", s.TraceHealth.EventsRecorded)
	}
	if s.TraceHealth.EventsDropped != 0 {
		t.Errorf("EventsDropped = %d, want 0 (no stderr input)", s.TraceHealth.EventsDropped)
	}
}

func TestParseIGStderr_SumsLostSamples(t *testing.T) {
	// Real ig v0.51.0 stderr shape: logrus-formatted warnings with the
	// "lost N samples" tail. Multiple lines must sum.
	stderr := `time="2026-04-20T12:00:00Z" level=warning msg="reading event: lost 128 samples"
time="2026-04-20T12:00:03Z" level=warning msg="reading event: lost 64 samples"
time="2026-04-20T12:00:05Z" level=info msg="ready"
`
	got := parseIGStderr(strings.NewReader(stderr), nil)
	if got != 128+64 {
		t.Errorf("parseIGStderr = %d, want %d", got, 128+64)
	}
}

func TestFinaliseTraceHealth_RateIsDroppedOverRecorded(t *testing.T) {
	th := TraceHealth{EventsRecorded: 100, EventsDropped: 2}
	finaliseTraceHealth(&th)
	if th.DropRate != 0.02 {
		t.Errorf("DropRate = %v, want 0.02", th.DropRate)
	}
}

func TestAggregate_MultiReplicaUnionAndDisagreement(t *testing.T) {
	// Two replicas, same image, divergent caps. With --all-matching, the
	// union lands in Capabilities and the per-replica-missing caps land
	// in ReplicaCapDisagreement.
	input := ev("timestamp", "1000", "cap", "CAP_CHOWN", "containerId", "r1", "containerName", "web-1", "image", "app:1") +
		ev("timestamp", "1010", "cap", "CAP_SETUID", "containerId", "r1", "containerName", "web-1", "image", "app:1") +
		ev("timestamp", "1020", "cap", "CAP_FOWNER", "containerId", "r1", "containerName", "web-1", "image", "app:1") +
		ev("timestamp", "1000", "cap", "CAP_CHOWN", "containerId", "r2", "containerName", "web-2", "image", "app:1") +
		ev("timestamp", "1010", "cap", "CAP_SETUID", "containerId", "r2", "containerName", "web-2", "image", "app:1")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Image: "app:1", AllMatching: true})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if s.Target.ReplicasObserved != 2 {
		t.Errorf("ReplicasObserved = %d, want 2", s.Target.ReplicasObserved)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN", "FOWNER", "SETUID"}) {
		t.Errorf("union = %v, want [CHOWN FOWNER SETUID]", s.CapNames())
	}
	if !equalSlice(s.Target.ReplicaCapDisagreement, []string{"FOWNER"}) {
		t.Errorf("disagreement = %v, want [FOWNER]", s.Target.ReplicaCapDisagreement)
	}
	if !equalSlice(s.Target.PerReplicaCaps["r1"], []string{"CHOWN", "FOWNER", "SETUID"}) {
		t.Errorf("r1 caps = %v", s.Target.PerReplicaCaps["r1"])
	}
	if !equalSlice(s.Target.PerReplicaCaps["r2"], []string{"CHOWN", "SETUID"}) {
		t.Errorf("r2 caps = %v", s.Target.PerReplicaCaps["r2"])
	}
	if s.Target.PerReplicaEventCounts["r1"] != 3 || s.Target.PerReplicaEventCounts["r2"] != 2 {
		t.Errorf("event counts wrong: %v", s.Target.PerReplicaEventCounts)
	}
	if s.Target.Mode != TargetModeAllMatching {
		t.Errorf("mode = %q, want %q", s.Target.Mode, TargetModeAllMatching)
	}
}

func TestAggregate_MultiReplicaAmbiguityWithoutAllMatching(t *testing.T) {
	// --image matching >1 replica without --all-matching must error -- the
	// tool refuses to silently union replicas (PLAN.md §Target selection).
	input := ev("cap", "CAP_CHOWN", "containerId", "r1", "containerName", "web-1", "image", "app:1") +
		ev("cap", "CAP_CHOWN", "containerId", "r2", "containerName", "web-2", "image", "app:1")
	_, err := aggregate(strings.NewReader(input), aggregateOpts{Image: "app:1"})
	if err == nil {
		t.Fatal("expected ambiguity error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "--all-matching") || !strings.Contains(msg, "web-1") || !strings.Contains(msg, "web-2") {
		t.Errorf("error does not guide the user: %q", msg)
	}
}

func TestAggregate_SingleReplicaHasEmptyDisagreement(t *testing.T) {
	input := ev("cap", "CAP_CHOWN", "containerId", "r1", "image", "app:1")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Image: "app:1"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if s.Target.ReplicasObserved != 1 {
		t.Errorf("ReplicasObserved = %d, want 1", s.Target.ReplicasObserved)
	}
	if len(s.Target.ReplicaCapDisagreement) != 0 {
		t.Errorf("single replica should have empty disagreement, got %v", s.Target.ReplicaCapDisagreement)
	}
	if s.Target.Mode != TargetModeImage {
		t.Errorf("mode = %q, want %q", s.Target.Mode, TargetModeImage)
	}
}

func TestAggregate_MultiReplicaInitWindowPerReplica(t *testing.T) {
	// Each replica gets its own init window, anchored on that replica's
	// first matching event. A late-joining replica isn't held to the
	// observation-start timestamp.
	input := ev("timestamp", "1000", "cap", "CAP_SYS_ADMIN", "containerId", "r1", "image", "app:1") +
		ev("timestamp", "1600", "cap", "CAP_CHOWN", "containerId", "r1", "image", "app:1") +
		ev("timestamp", "5000", "cap", "CAP_SYS_ADMIN", "containerId", "r2", "image", "app:1") +
		ev("timestamp", "5600", "cap", "CAP_CHOWN", "containerId", "r2", "image", "app:1")
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Image: "app:1", AllMatching: true, InitWindowMs: 500})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	// Both replicas should have filtered out their own SYS_ADMIN.
	if !equalSlice(s.Target.PerReplicaCaps["r1"], []string{"CHOWN"}) ||
		!equalSlice(s.Target.PerReplicaCaps["r2"], []string{"CHOWN"}) {
		t.Errorf("per-replica init filter failed: %+v", s.Target.PerReplicaCaps)
	}
	if s.Target.InitWindowSuppressed != 2 {
		t.Errorf("InitWindowSuppressed = %d, want 2 (one per replica)", s.Target.InitWindowSuppressed)
	}
}

func TestRun_ContainerAndImageMutuallyExclusive(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "x", "--image", "y"}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected error for --container + --image together")
	}
}

func TestRun_AllMatchingRequiresImage(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "x", "--all-matching"}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected error for --all-matching without --image")
	}
}

func TestRun_FixtureMode_AllMatchingPostgres(t *testing.T) {
	// Fixture has two postgres replicas: postgres-1 (CHOWN, DAC_OVERRIDE,
	// FOWNER, SETGID, SETUID) and postgres-2 (missing FOWNER). --image
	// with --all-matching must union them and surface FOWNER as the only
	// disagreement.
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--image", "postgres:16",
		"--all-matching",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	want := "cap_drop:\n  - ALL\ncap_add:\n  - CHOWN\n  - DAC_OVERRIDE\n  - FOWNER\n  - SETGID\n  - SETUID\n"
	if out.String() != want {
		t.Errorf("output mismatch:\ngot:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestRun_RequiresContainerOrFixture(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected error when neither --container nor --fixture given")
	}
}

func TestRun_WorkloadPopulatesSidecar(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "exercise.sh")
	if err := os.WriteFile(wl, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatalf("write workload: %v", err)
	}
	out := filepath.Join(dir, "sidecar.json")
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--workload", wl,
		"--out", out,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var s Sidecar
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Workload != wl {
		t.Errorf("Workload = %q, want %q", s.Workload, wl)
	}
}

func TestRun_WorkloadMissingFileFailsEXUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--workload", "/nonexistent/path/exercise.sh",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing workload file, got nil")
	}
	if exitCodeFor(err) != ExitUsage {
		t.Errorf("exit code = %d, want %d (EX_USAGE)", exitCodeFor(err), ExitUsage)
	}
	if !strings.Contains(err.Error(), "--workload") {
		t.Errorf("error should name the flag: %v", err)
	}
}

func TestMain_FixtureExists(t *testing.T) {
	// Sanity: fixture referenced by TestRun_FixtureMode must exist.
	if _, err := os.Stat("testdata/ig-versions/v0.51.0/sample.ndjson"); err != nil {
		t.Fatalf("testdata/ig-versions/v0.51.0/sample.ndjson missing: %v", err)
	}
}

func TestLooksLikeWSL2(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"native linux 6.x", "Linux version 6.17.0-20-generic (buildd@lcy02-amd64-001) (gcc ...) #20-Ubuntu SMP", false},
		{"empty", "", false},
		// WSL2 5.10 / 5.15 build banner.
		{"microsoft-standard-WSL2", "Linux version 5.15.146.1-microsoft-standard-WSL2 (root@build) (gcc ...) #1 SMP", true},
		// Older WSL2 5.10 banner that omits the explicit WSL2 token.
		{"microsoft-standard only", "Linux version 5.10.16.3-microsoft-standard (oe-user@oe-host) (gcc ...) #1 SMP", true},
		// Mixed-case sanity (banners have been lower-case to date but we
		// fold for safety).
		{"uppercase token", "Linux version 5.15.0-MICROSOFT-STANDARD-WSL2", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeWSL2(tc.in); got != tc.want {
				t.Errorf("looksLikeWSL2(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
