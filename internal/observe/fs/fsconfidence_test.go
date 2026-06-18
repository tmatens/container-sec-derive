package fs

import (
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// TestComputeFSConfidence exercises each grade branch of the fs rubric. base()
// is a clean "moderate" observation (capped there by the deferred
// preconditions); each case mutates one input and asserts the resulting grade.
func TestComputeFSConfidence(t *testing.T) {
	base := func() *sidecar.Sidecar {
		s := sidecar.NewSidecar()
		s.TraceHealth.EventsRecorded = 1500
		s.DurationSeconds = 300
		s.Workload = "/some/workload.sh"
		return s
	}
	cases := []struct {
		name string
		mut  func(*sidecar.Sidecar)
		want string
	}{
		{"healthy → moderate (capped)", func(s *sidecar.Sidecar) {}, sidecar.ConfidenceModerate},
		{"sparse events force low", func(s *sidecar.Sidecar) { s.TraceHealth.EventsRecorded = 5 }, sidecar.ConfidenceLow},
		{"drop rate >=1% low", func(s *sidecar.Sidecar) { s.TraceHealth.DropRate = 0.02 }, sidecar.ConfidenceLow},
		{"drop rate sub-1% → one moderate", func(s *sidecar.Sidecar) { s.TraceHealth.DropRate = 0.005 }, sidecar.ConfidenceModerate},
		{"duration floor low", func(s *sidecar.Sidecar) { s.DurationSeconds = 30 }, sidecar.ConfidenceLow},
		{"disagreement >1 low", func(s *sidecar.Sidecar) { s.Target.ReplicaWritePathDisagreement = []string{"/a", "/b"} }, sidecar.ConfidenceLow},
		{"disagreement 1 → one moderate", func(s *sidecar.Sidecar) { s.Target.ReplicaWritePathDisagreement = []string{"/a"} }, sidecar.ConfidenceModerate},
		{"no workload → one moderate", func(s *sidecar.Sidecar) { s.Workload = "" }, sidecar.ConfidenceModerate},
		{"two moderate (mid events + no workload) → low", func(s *sidecar.Sidecar) {
			s.TraceHealth.EventsRecorded = 500
			s.Workload = ""
		}, sidecar.ConfidenceLow},
		{"mid events + workload → one moderate", func(s *sidecar.Sidecar) { s.TraceHealth.EventsRecorded = 500 }, sidecar.ConfidenceModerate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			tc.mut(s)
			computeFSConfidence(s)
			if s.Confidence.Level != tc.want {
				t.Errorf("level = %q, want %q; factors=%v", s.Confidence.Level, tc.want, s.Confidence.Factors)
			}
			// The grade must always be reproducible from a non-empty factor list.
			if len(s.Confidence.Factors) == 0 {
				t.Error("Confidence.Factors is empty; grade is not auditable")
			}
		})
	}
}
