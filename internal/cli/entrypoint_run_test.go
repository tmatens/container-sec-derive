package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression: Run() with a clean cross-check (no warnings) must still
// serialize `"coverage_warnings":[]`, not `"coverage_warnings":null`.
func TestRun_CleanCrossCheckSerializesEmptySlice(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "sidecar.json")
	var stdout, stderr bytes.Buffer
	err := Run([]string{
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson",
		"--inspect-fixture", "../../testdata/entrypoint/postgres_argv_only.json",
		"--container", "postgres-1",
		"--out", out,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, `"coverage_warnings": []`) {
		t.Errorf("coverage_warnings must be [] not null in clean cross-check sidecar:\n%s", text)
	}
	if !strings.Contains(text, `"expected_caps_from_entrypoint": []`) {
		t.Errorf("expected_caps_from_entrypoint must be [] not null in clean cross-check sidecar:\n%s", text)
	}
}
