package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// #209: under sudo the sidecar is created root:root 0600 and the invoking user
// can't read their own evidence. writeSidecar chowns it back to SUDO_UID/GID
// while preserving 0600. Chowning to a *different* uid needs root, so we assert
// the mechanism with a self-chown (SUDO_UID = current uid, which succeeds
// unprivileged) and assert non-sudo runs are left untouched.
func TestWriteSidecar_ChownAndMode(t *testing.T) {
	me := os.Getuid()
	t.Run("sudo: chowns to SUDO_UID, keeps 0600", func(t *testing.T) {
		t.Setenv("SUDO_UID", strconv.Itoa(me))
		t.Setenv("SUDO_GID", strconv.Itoa(os.Getgid()))
		path := filepath.Join(t.TempDir(), "sidecar.json")
		if err := writeSidecar(sidecar.NewSidecar(), path); err != nil {
			t.Fatalf("writeSidecar: %v", err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %o, want 0600 (chown must not widen perms)", perm)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != me {
			t.Errorf("owner uid = %d, want %d (SUDO_UID)", st.Uid, me)
		}
	})
	t.Run("non-sudo: no SUDO_UID, still written 0600", func(t *testing.T) {
		t.Setenv("SUDO_UID", "")
		t.Setenv("SUDO_GID", "")
		path := filepath.Join(t.TempDir(), "sidecar.json")
		if err := writeSidecar(sidecar.NewSidecar(), path); err != nil {
			t.Fatalf("writeSidecar: %v", err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %o, want 0600", perm)
		}
	})
}

func TestNewSidecar_Constants(t *testing.T) {
	s := sidecar.NewSidecar()
	if s.SchemaVersion != "1.5" {
		t.Errorf("SchemaVersion = %q, want %q", s.SchemaVersion, "1.5")
	}
	if s.ToolVersion != "0.7.0" {
		t.Errorf("ToolVersion = %q, want %q", s.ToolVersion, "0.7.0")
	}
	if !strings.Contains(s.Caveat, "not a correctness proof") && !strings.Contains(s.Caveat, "Not a correctness proof") {
		t.Errorf("Caveat missing the correctness-proof framing: %q", s.Caveat)
	}
}

// JSON should never emit `null` for collection fields. Downstream parsers
// (including the compose-lint contribution flow) treat null arrays as
// schema drift, so the constructor must pre-initialize every slice/map.
func TestNewSidecar_NoNullCollections(t *testing.T) {
	s := sidecar.NewSidecar()
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
	b, err := json.Marshal(sidecar.NewSidecar())
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
