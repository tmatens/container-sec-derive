package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestAggregate_DistinctCapsSorted(t *testing.T) {
	input := `{"capName":"CAP_CHOWN","container":{"id":"abc123def456","name":"pg"}}
{"capName":"CAP_SETUID","container":{"id":"abc123def456","name":"pg"}}
{"capName":"CAP_CHOWN","container":{"id":"abc123def456","name":"pg"}}
{"capName":"CAP_DAC_OVERRIDE","container":{"id":"abc123def456","name":"pg"}}
`
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
	input := `{"capName":"CAP_CHOWN","container":{"id":"aaa","name":"pg"}}
{"capName":"CAP_NET_RAW","container":{"id":"bbb","name":"other"}}
`
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "pg"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN"}) {
		t.Errorf("expected only CHOWN for pg, got %v", s.CapNames())
	}
}

func TestAggregate_ContainerIDPrefix(t *testing.T) {
	input := `{"capName":"CAP_SETGID","container":{"id":"abcdef1234567890","name":""}}` + "\n"
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "abcdef"})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"SETGID"}) {
		t.Errorf("prefix match failed, got %v", s.CapNames())
	}
}

func TestAggregate_EmptyTargetMatchesAll(t *testing.T) {
	input := `{"capName":"CAP_CHOWN","container":{"id":"a"}}
{"capName":"CAP_SETUID","container":{"id":"b"}}
`
	s, err := aggregate(strings.NewReader(input), aggregateOpts{})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN", "SETUID"}) {
		t.Errorf("got %v", s.CapNames())
	}
}

func TestAggregate_SkipsMalformedLines(t *testing.T) {
	input := "not json at all\n" +
		`{"capName":"CAP_CHOWN","container":{"id":"a"}}` + "\n" +
		"\n" + // blank line
		`{"capName":"CAP_SETUID","container":{"id":"a"}}` + "\n"
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
	input := `{"timestamp":1000,"capName":"CAP_SYS_ADMIN","container":{"id":"a"}}
{"timestamp":1100,"capName":"CAP_DAC_READ_SEARCH","container":{"id":"a"}}
{"timestamp":1600,"capName":"CAP_CHOWN","container":{"id":"a"}}
{"timestamp":1700,"capName":"CAP_SETUID","container":{"id":"a"}}
`
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
	input := `{"timestamp":1000,"capName":"CAP_SYS_ADMIN","container":{"id":"a"}}
{"timestamp":1600,"capName":"CAP_CHOWN","container":{"id":"a"}}
`
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

func TestAggregate_InitWindowIgnoresUnmatchedEvents(t *testing.T) {
	// Events for other containers must not anchor the init window for
	// the target. First *matching* event is the reference point.
	input := `{"timestamp":1000,"capName":"CAP_NET_RAW","container":{"id":"other"}}
{"timestamp":5000,"capName":"CAP_SYS_ADMIN","container":{"id":"a"}}
{"timestamp":5600,"capName":"CAP_CHOWN","container":{"id":"a"}}
`
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
	err := run([]string{"--fixture", "testdata/sample.ndjson", "--container", "postgres-1"}, &out, &errBuf)
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

func TestAggregate_TraceHealthPopulated(t *testing.T) {
	input := `{"timestamp":1000,"capName":"CAP_CHOWN","container":{"id":"a"}}
{"timestamp":1600,"capName":"CAP_SETUID","container":{"id":"a"}}
{"type":"trace_health","events_recorded":200,"events_dropped":2}
`
	s, err := aggregate(strings.NewReader(input), aggregateOpts{Container: "a", InitWindowMs: 500})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if s.TraceHealth.EventsRecorded != 200 || s.TraceHealth.EventsDropped != 2 {
		t.Errorf("trace_health not captured: %+v", s.TraceHealth)
	}
	if s.TraceHealth.DropRate != 0.01 {
		t.Errorf("DropRate = %v, want 0.01", s.TraceHealth.DropRate)
	}
}

func TestAggregate_TraceHealthLastWins(t *testing.T) {
	input := `{"type":"trace_health","events_recorded":100,"events_dropped":0}
{"type":"trace_health","events_recorded":250,"events_dropped":5}
`
	s, err := aggregate(strings.NewReader(input), aggregateOpts{})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if s.TraceHealth.EventsRecorded != 250 || s.TraceHealth.EventsDropped != 5 {
		t.Errorf("expected last trace_health to win, got %+v", s.TraceHealth)
	}
}

func TestAggregate_TraceHealthLinesDoNotFeedCaps(t *testing.T) {
	// A trace_health line must never be misread as a cap event.
	input := `{"type":"trace_health","events_recorded":10,"events_dropped":0}
`
	s, err := aggregate(strings.NewReader(input), aggregateOpts{})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if len(s.Capabilities) != 0 {
		t.Errorf("trace_health leaked into caps: %v", s.CapNames())
	}
}

func TestAggregate_MultiReplicaUnionAndDisagreement(t *testing.T) {
	// Two replicas, same image, divergent caps. With --all-matching, the
	// union lands in Capabilities and the per-replica-missing caps land
	// in ReplicaCapDisagreement.
	input := `{"timestamp":1000,"capName":"CAP_CHOWN","container":{"id":"r1","name":"web-1","image":"app:1"}}
{"timestamp":1010,"capName":"CAP_SETUID","container":{"id":"r1","name":"web-1","image":"app:1"}}
{"timestamp":1020,"capName":"CAP_FOWNER","container":{"id":"r1","name":"web-1","image":"app:1"}}
{"timestamp":1000,"capName":"CAP_CHOWN","container":{"id":"r2","name":"web-2","image":"app:1"}}
{"timestamp":1010,"capName":"CAP_SETUID","container":{"id":"r2","name":"web-2","image":"app:1"}}
`
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
	input := `{"capName":"CAP_CHOWN","container":{"id":"r1","name":"web-1","image":"app:1"}}
{"capName":"CAP_CHOWN","container":{"id":"r2","name":"web-2","image":"app:1"}}
`
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
	input := `{"capName":"CAP_CHOWN","container":{"id":"r1","image":"app:1"}}
`
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
	input := `{"timestamp":1000,"capName":"CAP_SYS_ADMIN","container":{"id":"r1","image":"app:1"}}
{"timestamp":1600,"capName":"CAP_CHOWN","container":{"id":"r1","image":"app:1"}}
{"timestamp":5000,"capName":"CAP_SYS_ADMIN","container":{"id":"r2","image":"app:1"}}
{"timestamp":5600,"capName":"CAP_CHOWN","container":{"id":"r2","image":"app:1"}}
`
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
	err := run([]string{"--fixture", "testdata/sample.ndjson", "--container", "x", "--image", "y"}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected error for --container + --image together")
	}
}

func TestRun_AllMatchingRequiresImage(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{"--fixture", "testdata/sample.ndjson", "--container", "x", "--all-matching"}, &out, &errBuf)
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
		"--fixture", "testdata/sample.ndjson",
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

func TestMain_FixtureExists(t *testing.T) {
	// Sanity: fixture referenced by TestRun_FixtureMode must exist.
	if _, err := os.Stat("testdata/sample.ndjson"); err != nil {
		t.Fatalf("testdata/sample.ndjson missing: %v", err)
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
