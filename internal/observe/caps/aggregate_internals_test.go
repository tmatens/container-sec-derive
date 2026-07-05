package caps

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
)

// White-box tests for the pure-Go aggregation core (#289). The golden-fixture
// replay in internal/cli exercises the whole pipeline end-to-end, but a
// counting / first-seen / init-filter bug that still produced the same cap set
// would pass the golden and ship undetected. These pin the intermediate
// numbers — event counts, suppression accounting, offsets, per-replica split —
// that the golden JSON does not force.

// evFull builds one trace_capabilities NDJSON line with every field Aggregate
// reads. Timestamps are milliseconds (the pinned-ig fixture convention).
func evFull(ts int64, capName, comm, cid, cname string, capable bool) string {
	return fmt.Sprintf(
		`{"timestamp":%d,"cap":%q,"capable":%t,`+
			`"proc":{"comm":%q,"pid":0},`+
			`"runtime":{"runtimeName":"docker","containerId":%q,"containerName":%q,"containerImageName":"postgres:16"}}`+"\n",
		ts, capName, capable, comm, cid, cname)
}

func TestAggregate_InitWindowSuppressionAndOffsets(t *testing.T) {
	// InitWindowMs=500: an event lands in the cap set only when it fires >=500ms
	// after the replica's first matching event. The first event (offset 0) and
	// any within the window are suppressed and counted, not dropped silently.
	in := evFull(1000, "CAP_CHOWN", "worker", "abc123def456", "pg", true) + // 0 < 500  -> suppressed
		evFull(1400, "CAP_CHOWN", "worker", "abc123def456", "pg", true) + // 400 < 500 -> suppressed
		evFull(1600, "CAP_CHOWN", "worker", "abc123def456", "pg", true) + // 600 >=500 -> kept
		evFull(1700, "CAP_SETUID", "worker", "abc123def456", "pg", true) // 700 >=500 -> kept

	s, err := Aggregate(strings.NewReader(in), attrib.Opts{Container: "pg", InitWindowMs: 500})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if got, want := s.Target.InitWindowSuppressed, 2; got != want {
		t.Errorf("InitWindowSuppressed = %d, want %d", got, want)
	}
	if got, want := s.CapNames(), []string{"CHOWN", "SETUID"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("caps = %v, want %v", got, want)
	}
	// Offsets are relative to the earliest KEPT event across the profile (1600).
	byName := map[string]int64{}
	counts := map[string]int{}
	for _, c := range s.Capabilities {
		byName[c.Name] = c.FirstSeenOffsetMs
		counts[c.Name] = c.EventCount
	}
	if byName["CHOWN"] != 0 {
		t.Errorf("CHOWN first-seen offset = %d, want 0 (it is the global-first kept event)", byName["CHOWN"])
	}
	if byName["SETUID"] != 100 {
		t.Errorf("SETUID first-seen offset = %d, want 100 (1700-1600)", byName["SETUID"])
	}
	if counts["CHOWN"] != 1 {
		t.Errorf("CHOWN event_count = %d, want 1 (only the kept event is aggregated)", counts["CHOWN"])
	}
}

func TestAggregate_InitCommSuppressedRegardlessOfTime(t *testing.T) {
	// A runc:[*] init event is suppressed by comm even far past the time window
	// (InitWindowMs=0 disables the time filter entirely), so it can't leak a
	// container-bring-up cap into the workload profile.
	in := evFull(5000, "CAP_CHOWN", "runc:[0:INIT]", "abc123def456", "pg", true) + // init comm -> suppressed
		evFull(5001, "CAP_CHOWN", "postgres", "abc123def456", "pg", true) // real workload -> kept

	s, err := Aggregate(strings.NewReader(in), attrib.Opts{Container: "pg", InitWindowMs: 0})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if got, want := s.Target.InitWindowSuppressed, 1; got != want {
		t.Errorf("InitWindowSuppressed = %d, want %d (the runc: event)", got, want)
	}
	if got := s.CapNames(); len(got) != 1 || got[0] != "CHOWN" {
		t.Fatalf("caps = %v, want [CHOWN]", got)
	}
	for _, c := range s.Capabilities {
		if c.Name == "CHOWN" && c.EventCount != 1 {
			t.Errorf("CHOWN event_count = %d, want 1 (init event not counted into the cap)", c.EventCount)
		}
	}
}

func TestAggregate_NonCapableCountedButExcluded(t *testing.T) {
	// A capable=false event is a kretprobe-recorded denial: it counts toward
	// events_recorded (the drop-rate denominator) but must NOT enter the derived
	// cap set — that would be the dangerous direction (granting a denied cap).
	in := evFull(1000, "CAP_SYS_ADMIN", "worker", "abc123def456", "pg", false) + // denial
		evFull(1001, "CAP_CHOWN", "worker", "abc123def456", "pg", true)

	s, err := Aggregate(strings.NewReader(in), attrib.Opts{Container: "pg", InitWindowMs: 0})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if got := s.CapNames(); len(got) != 1 || got[0] != "CHOWN" {
		t.Errorf("caps = %v, want [CHOWN] (denied SYS_ADMIN excluded)", got)
	}
	if got, want := s.TraceHealth.EventsRecorded, 2; got != want {
		t.Errorf("EventsRecorded = %d, want %d (both the denial and the grant are parsed samples)", got, want)
	}
}

func TestAggregate_MultiReplicaDisagreement(t *testing.T) {
	// Under --all-matching two replicas union their caps, and any cap missing
	// from some replica is recorded in ReplicaCapDisagreement (which drives the
	// confidence rubric's divergence factor).
	in := evFull(1000, "CAP_CHOWN", "worker", "cidAAAAAA", "pgA", true) +
		evFull(1001, "CAP_SETUID", "worker", "cidAAAAAA", "pgA", true) +
		evFull(1002, "CAP_CHOWN", "worker", "cidBBBBBB", "pgB", true) // pgB lacks SETUID

	s, err := Aggregate(strings.NewReader(in), attrib.Opts{Image: "postgres:16", AllMatching: true, InitWindowMs: 0})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if s.Target.ReplicasObserved != 2 {
		t.Errorf("ReplicasObserved = %d, want 2", s.Target.ReplicasObserved)
	}
	if got := s.Target.ReplicaCapDisagreement; len(got) != 1 || got[0] != "SETUID" {
		t.Errorf("ReplicaCapDisagreement = %v, want [SETUID]", got)
	}
	if got := s.Target.PerReplicaCaps["cidBBBBBB"]; len(got) != 1 || got[0] != "CHOWN" {
		t.Errorf("PerReplicaCaps[pgB] = %v, want [CHOWN]", got)
	}
	if got := strings.Join(s.CapNames(), ","); got != "CHOWN,SETUID" {
		t.Errorf("union caps = %q, want CHOWN,SETUID", got)
	}
}

func TestAggregate_AmbiguousImageWithoutAllMatchingErrors(t *testing.T) {
	// --image matching >1 replica without --all-matching must be a typed error,
	// never a silent union (PLAN.md §Target selection).
	in := evFull(1000, "CAP_CHOWN", "worker", "cidAAAAAA", "pgA", true) +
		evFull(1001, "CAP_CHOWN", "worker", "cidBBBBBB", "pgB", true)

	_, err := Aggregate(strings.NewReader(in), attrib.Opts{Image: "postgres:16", InitWindowMs: 0})
	if err == nil {
		t.Fatal("expected ambiguity error for --image matching two replicas")
	}
	var amb *exit.AmbiguousSelectionError
	if !errors.As(err, &amb) {
		t.Errorf("error should be a typed AmbiguousSelectionError, got %T: %v", err, err)
	}
}

func TestAggregate_MalformedLineHardFails(t *testing.T) {
	// A malformed line is a hard error, not a skip: silently skipping would
	// shrink the derived cap set with no signal (deep-review L3).
	_, err := Aggregate(strings.NewReader("{ this is not json\n"), attrib.Opts{Container: "pg"})
	if err == nil {
		t.Fatal("expected a parse error on malformed input")
	}
	if !strings.Contains(err.Error(), "parse trace_capabilities") {
		t.Errorf("error should name the parse failure, got %v", err)
	}
}

func TestNormalizeCap(t *testing.T) {
	cases := map[string]string{
		"CAP_NET_RAW": "NET_RAW",
		"net_raw":     "NET_RAW",
		" CAP_chown ": "CHOWN",
		"SETUID":      "SETUID",
		"":            "",
	}
	for in, want := range cases {
		if got := NormalizeCap(in); got != want {
			t.Errorf("NormalizeCap(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCapStatsObserve(t *testing.T) {
	// The per-cap collapser: count, min-first / max-last timestamp, deduped comms.
	c := newCapStats()
	c.observe(2000, "postgres")
	c.observe(1500, "postgres") // earlier ts -> updates firstTsMs, dedup comm
	c.observe(3000, "checkpointer")
	if c.eventCount != 3 {
		t.Errorf("eventCount = %d, want 3", c.eventCount)
	}
	if c.firstTsMs != 1500 {
		t.Errorf("firstTsMs = %d, want 1500 (min)", c.firstTsMs)
	}
	if c.lastTsMs != 3000 {
		t.Errorf("lastTsMs = %d, want 3000 (max)", c.lastTsMs)
	}
	if len(c.commSamples) != 2 {
		t.Errorf("commSamples = %v, want 2 distinct", c.commSamples)
	}
}
