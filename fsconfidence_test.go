package main

import "testing"

// TestComputeFSConfidence exercises each grade branch of the fs rubric. base()
// is a clean "moderate" observation (capped there by the deferred
// preconditions); each case mutates one input and asserts the resulting grade.
func TestComputeFSConfidence(t *testing.T) {
	base := func() *Sidecar {
		s := NewSidecar()
		s.TraceHealth.EventsRecorded = 1500
		s.DurationSeconds = 300
		s.Workload = "/some/workload.sh"
		return s
	}
	cases := []struct {
		name string
		mut  func(*Sidecar)
		want string
	}{
		{"healthy → moderate (capped)", func(s *Sidecar) {}, ConfidenceModerate},
		{"sparse events force low", func(s *Sidecar) { s.TraceHealth.EventsRecorded = 5 }, ConfidenceLow},
		{"drop rate >=1% low", func(s *Sidecar) { s.TraceHealth.DropRate = 0.02 }, ConfidenceLow},
		{"drop rate sub-1% → one moderate", func(s *Sidecar) { s.TraceHealth.DropRate = 0.005 }, ConfidenceModerate},
		{"duration floor low", func(s *Sidecar) { s.DurationSeconds = 30 }, ConfidenceLow},
		{"disagreement >1 low", func(s *Sidecar) { s.Target.ReplicaWritePathDisagreement = []string{"/a", "/b"} }, ConfidenceLow},
		{"disagreement 1 → one moderate", func(s *Sidecar) { s.Target.ReplicaWritePathDisagreement = []string{"/a"} }, ConfidenceModerate},
		{"no workload → one moderate", func(s *Sidecar) { s.Workload = "" }, ConfidenceModerate},
		{"two moderate (mid events + no workload) → low", func(s *Sidecar) {
			s.TraceHealth.EventsRecorded = 500
			s.Workload = ""
		}, ConfidenceLow},
		{"mid events + workload → one moderate", func(s *Sidecar) { s.TraceHealth.EventsRecorded = 500 }, ConfidenceModerate},
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
