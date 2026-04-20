package main

import "time"

// Canonical evidence-artifact identity fields.
//
// SchemaVersion follows semver-on-schema: additive changes stay within 1.x;
// consumers (including the compose-lint contribution flow) reject unknown
// majors. See PLAN.md §Output schema.
const (
	SchemaVersion = "1.0"
	ToolVersion   = "0.1.0-alpha"
	// Caveat is hardcoded so downstream consumers cannot strip the
	// "this is workload-bounded, not a correctness proof" framing.
	Caveat = "BPF-observed profiles reflect only the paths the workload exercised. Not a correctness proof."
)

// Confidence levels. String values match PLAN.md §Confidence scoring.
const (
	ConfidenceHigh     = "high"
	ConfidenceModerate = "moderate"
	ConfidenceLow      = "low"
)

// Target selection modes. Values match PLAN.md §Target selection.
const (
	TargetModeContainer   = "container"
	TargetModeImage       = "image"
	TargetModeAllMatching = "all-matching"
)

// Sidecar is the canonical JSON evidence artifact. All formatters derive
// from this struct; it is the single source of truth for an observation run.
// See PLAN.md §Output schema for the full field-by-field contract.
type Sidecar struct {
	SchemaVersion              string       `json:"schema_version"`
	Image                      string       `json:"image,omitempty"`
	ImageDigest                string       `json:"image_digest,omitempty"`
	ObservedAt                 time.Time    `json:"observed_at"`
	DurationSeconds            int          `json:"duration_seconds"`
	Workload                   string       `json:"workload,omitempty"`
	ToolVersion                string       `json:"tool_version"`
	KernelVersion              string       `json:"kernel_version,omitempty"`
	Target                     Target       `json:"target"`
	Capabilities               []Capability `json:"capabilities"`
	ExpectedCapsFromEntrypoint []string     `json:"expected_caps_from_entrypoint"`
	CoverageWarnings           []string     `json:"coverage_warnings"`
	TraceHealth                TraceHealth  `json:"trace_health"`
	Confidence                 Confidence   `json:"confidence"`
	Caveat                     string       `json:"caveat"`
}

// Target captures which container(s) produced the observation and how
// selection + restart handling played out over the window.
type Target struct {
	Mode                   string              `json:"mode"`
	Selector               string              `json:"selector"`
	ReplicasObserved       int                 `json:"replicas_observed"`
	PerReplicaEventCounts  map[string]int      `json:"per_replica_event_counts"`
	PerReplicaCaps         map[string][]string `json:"per_replica_caps"`
	ReplicaCapDisagreement []string            `json:"replica_cap_disagreement"`
	Restarts               []Restart           `json:"restarts"`
	FollowRestart          bool                `json:"follow_restart"`
	TargetExitedEarly      bool                `json:"target_exited_early"`
	// InitWindowSuppressed is how many events the init-window filter
	// dropped. Exposed so reviewers can tell whether a sparse derived
	// cap set is genuine workload behavior or a window-too-wide artifact.
	InitWindowSuppressed int `json:"init_window_suppressed"`
	// DistinctComms is the count of distinct `comm` values observed across
	// all replicas after the init-window filter. Feeds the comm-diversity
	// factor in PLAN.md §Confidence scoring. Tracked here (rather than in
	// a private aggregator field) so reviewers can audit the rubric input
	// from the sidecar alone.
	DistinctComms int `json:"distinct_comms"`
}

// Restart records a single exit-during-observation event. Attribution is
// cgroup-id-keyed (PLAN.md §Target selection), so a new container sharing
// the image ref is a different subject and does not merge here.
type Restart struct {
	AtOffsetMs int64  `json:"at_offset_ms"`
	ExitCode   int    `json:"exit_code"`
	Reason     string `json:"reason"` // "signal" | "oom" | "normal"
}

// Capability is one distinct capability observed during the window. The
// aggregator collapses N raw events per cap into a single entry with
// counts and offsets for reviewer auditability.
type Capability struct {
	Name              string   `json:"name"`
	EventCount        int      `json:"event_count"`
	FirstSeenOffsetMs int64    `json:"first_seen_offset_ms"`
	LastSeenOffsetMs  int64    `json:"last_seen_offset_ms"`
	CommSamples       []string `json:"comm_samples"`
}

// TraceHealth surfaces the IG ringbuf drop counter (PLAN.md §Event-loss
// reporting). Always emitted; never hidden. drop_rate >= 1% downgrades
// confidence; >= 10% aborts emission.
type TraceHealth struct {
	EventsRecorded int     `json:"events_recorded"`
	EventsDropped  int     `json:"events_dropped"`
	DropRate       float64 `json:"drop_rate"`
}

// Confidence is PLAN.md §Confidence scoring's mechanical output. Level is
// reproducible from Factors — reviewers must be able to trace the grade
// back to the evidence.
type Confidence struct {
	Level   string   `json:"level"`
	Factors []string `json:"factors"`
}

// CapNames returns the capability names from s.Capabilities in the order
// aggregate() stored them (sorted ascending). Formatters and the v0.1
// stdout path both go through this helper so the one source of truth for
// "the observed cap set" is the Sidecar, not a parallel slice.
func (s *Sidecar) CapNames() []string {
	out := make([]string, 0, len(s.Capabilities))
	for _, c := range s.Capabilities {
		out = append(out, c.Name)
	}
	return out
}

// NewSidecar returns a Sidecar with identity fields locked and every
// collection pre-initialized to empty (not nil). Empty vs null matters
// because downstream parsers (including the compose-lint contribution
// flow) treat `null` arrays as schema drift.
func NewSidecar() *Sidecar {
	return &Sidecar{
		SchemaVersion:              SchemaVersion,
		ToolVersion:                ToolVersion,
		Caveat:                     Caveat,
		Capabilities:               []Capability{},
		ExpectedCapsFromEntrypoint: []string{},
		CoverageWarnings:           []string{},
		Target: Target{
			PerReplicaEventCounts:  map[string]int{},
			PerReplicaCaps:         map[string][]string{},
			ReplicaCapDisagreement: []string{},
			Restarts:               []Restart{},
		},
		Confidence: Confidence{
			Factors: []string{},
		},
	}
}
