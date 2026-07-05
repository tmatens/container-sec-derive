package caps

import (
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// ev builds one trace_capabilities NDJSON event line in the pinned v0.51.0
// shape (only the fields Aggregate reads: timestamp, cap, capable, runtime).
func ev(capName, containerID, containerName string) string {
	return `{"timestamp":1700000000001,"cap":"` + capName + `","capable":true,` +
		`"proc":{"comm":"init","pid":0},` +
		`"runtime":{"runtimeName":"docker","containerId":"` + containerID +
		`","containerName":"` + containerName +
		`","containerImageName":"postgres:16"}}` + "\n"
}

// In-package coverage for the aggregation core: the bulk of the exercise lives
// in internal/cli (cross-package, so it doesn't count toward this package's
// coverage). These keep the dedup/sort and the confidence rubric guarded from
// within the package itself.

func TestAggregate_DistinctSortedCaps(t *testing.T) {
	in := ev("CAP_CHOWN", "abc123def456", "pg") +
		ev("CAP_SETUID", "abc123def456", "pg") +
		ev("CAP_CHOWN", "abc123def456", "pg") + // duplicate collapses
		ev("CAP_DAC_OVERRIDE", "abc123def456", "pg")
	s, err := Aggregate(strings.NewReader(in), attrib.Opts{Container: "pg"})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	got := s.CapNames()
	want := []string{"CHOWN", "DAC_OVERRIDE", "SETUID"} // stripped, deduped, sorted
	if len(got) != len(want) {
		t.Fatalf("caps = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("caps = %v, want %v", got, want)
		}
	}
}

func TestComputeConfidence_NoWorkloadRunIsBounded(t *testing.T) {
	// A no-workload run (no --workload, no inspect) can't clear the moderate
	// preconditions, so the rubric must not over-claim: the grade is bounded to
	// low/moderate and is backed by recorded factors (reproducibility contract).
	in := ev("CAP_CHOWN", "abc123def456", "pg")
	s, err := Aggregate(strings.NewReader(in), attrib.Opts{Container: "pg"})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	ComputeConfidence(s)
	switch s.Confidence.Level {
	case sidecar.ConfidenceLow, sidecar.ConfidenceModerate:
		// expected: deferred preconditions cap the grade here
	default:
		t.Errorf("Confidence.Level = %q, want low or moderate for a no-workload run", s.Confidence.Level)
	}
	if len(s.Confidence.Factors) == 0 {
		t.Error("Confidence.Factors must record why the grade was assigned")
	}
}
