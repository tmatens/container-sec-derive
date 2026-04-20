package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewSidecar_Constants(t *testing.T) {
	s := NewSidecar()
	if s.SchemaVersion != "1.0" {
		t.Errorf("SchemaVersion = %q, want %q", s.SchemaVersion, "1.0")
	}
	if s.ToolVersion != "0.1.0-alpha" {
		t.Errorf("ToolVersion = %q, want %q", s.ToolVersion, "0.1.0-alpha")
	}
	if !strings.Contains(s.Caveat, "not a correctness proof") && !strings.Contains(s.Caveat, "Not a correctness proof") {
		t.Errorf("Caveat missing the correctness-proof framing: %q", s.Caveat)
	}
}

// JSON should never emit `null` for collection fields. Downstream parsers
// (including the compose-lint contribution flow) treat null arrays as
// schema drift, so the constructor must pre-initialize every slice/map.
func TestNewSidecar_NoNullCollections(t *testing.T) {
	s := NewSidecar()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)

	mustContain := []string{
		`"capabilities":[]`,
		`"expected_caps_from_entrypoint":[]`,
		`"coverage_warnings":[]`,
		`"per_replica_event_counts":{}`,
		`"per_replica_caps":{}`,
		`"replica_cap_disagreement":[]`,
		`"restarts":[]`,
		`"factors":[]`,
	}
	for _, needle := range mustContain {
		if !strings.Contains(got, needle) {
			t.Errorf("JSON missing %s\nfull: %s", needle, got)
		}
	}
	if strings.Contains(got, `:null`) {
		t.Errorf("JSON contains null value; all collections must be empty, not null: %s", got)
	}
}

// Top-level JSON keys are part of the schema contract. If any rename or
// disappear, downstream consumers break — this test pins the shape.
func TestNewSidecar_TopLevelKeys(t *testing.T) {
	b, err := json.Marshal(NewSidecar())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	required := []string{
		"schema_version",
		"observed_at",
		"duration_seconds",
		"tool_version",
		"target",
		"capabilities",
		"expected_caps_from_entrypoint",
		"coverage_warnings",
		"trace_health",
		"confidence",
		"caveat",
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			t.Errorf("top-level key %q missing from JSON", k)
		}
	}

	// omitempty fields must be absent on a fresh sidecar
	omitempty := []string{"image", "image_digest", "workload", "kernel_version"}
	for _, k := range omitempty {
		if _, ok := m[k]; ok {
			t.Errorf("key %q should be omitted when empty, but appears in JSON", k)
		}
	}
}
