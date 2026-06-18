package fs

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tmatens/container-sec-derive/internal/attrib"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite golden files instead of comparing")

// TestFSSidecar_Golden pins the v0.2 fs observer's JSON shape — the additive
// writable_paths + fs_recommendation blocks alongside the empty capability
// scaffolding — against testdata/fs_sidecar_golden.json. Built from the
// committed trace_open fixture + the postgres mounts fixture; ObservedAt and
// DurationSeconds are fixed so the document is reproducible (same approach as
// TestSidecar_GoldenPostgres1). Run with -update-golden to refresh.
func TestFSSidecar_Golden(t *testing.T) {
	f, err := os.Open("../../../testdata/ig-versions/v0.51.0/trace_open_sample.ndjson")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	writes, err := aggregateWrites(f, attrib.Opts{Container: "postgres-1"})
	if err != nil {
		t.Fatalf("aggregateWrites: %v", err)
	}
	mounts, err := loadMountsFixture("../../../testdata/postgres/mounts.json")
	if err != nil {
		t.Fatalf("loadMountsFixture: %v", err)
	}
	s := fsToSidecar(writes, mounts, attrib.Opts{Container: "postgres-1"})
	s.ObservedAt = time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	s.DurationSeconds = 600
	computeFSConfidence(s)

	got, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("..", "..", "..", "testdata", "fs_sidecar_golden.json")
	if *updateGolden {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s (%d bytes)", goldenPath, len(got))
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update-golden to create)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("fs golden mismatch. Diff:\n--- want\n%s\n--- got\n%s", want, got)
	}
}
