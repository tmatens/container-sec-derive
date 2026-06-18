package format

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// TestWriteFSComposePatch_PlacementCases covers the read_only/tmpfs placement
// matrix beyond the insert-both case: replacing an existing read_only, an
// existing tmpfs, or both in place.
func TestWriteFSComposePatch_PlacementCases(t *testing.T) {
	rec := sidecar.FSRecommendation{ReadOnly: true, TmpfsPaths: []string{"/run"}}
	cases := []struct {
		name    string
		compose string
		want    []string
	}{
		{
			"read_only exists, tmpfs absent → replace read_only with combined",
			"services:\n  w:\n    image: x\n    read_only: false\n",
			[]string{"-    read_only: false", "+    read_only: true", "+    tmpfs:", "+      - /run"},
		},
		{
			"tmpfs exists, read_only absent → replace tmpfs with combined",
			"services:\n  w:\n    image: x\n    tmpfs:\n      - /old\n",
			[]string{"-    tmpfs:", "-      - /old", "+    read_only: true", "+      - /run"},
		},
		{
			"both exist → replace both in place",
			"services:\n  w:\n    image: x\n    read_only: false\n    tmpfs:\n      - /old\n",
			[]string{"-    read_only: false", "+    read_only: true", "-      - /old", "+      - /run"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := WriteFSComposePatch(&b, rec, []byte(tc.compose), "c.yml", "w"); err != nil {
				t.Fatal(err)
			}
			for _, w := range tc.want {
				if !strings.Contains(b.String(), w) {
					t.Errorf("patch missing %q:\n%s", w, b.String())
				}
			}
		})
	}
}

// TestCheckFSComposeLintContract exercises each acceptance-contract violation
// branch (the CL-0007 gate). Starts from a clean, passing sidecar and mutates
// one field per case.
func TestCheckFSComposeLintContract(t *testing.T) {
	wl := filepath.Join(t.TempDir(), "wl.sh")
	if err := os.WriteFile(wl, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := func() *sidecar.Sidecar {
		s := sidecar.NewSidecar()
		s.ImageDigest = "sha256:abc"
		s.Workload = wl
		s.DurationSeconds = 600
		s.Confidence.Level = sidecar.ConfidenceModerate
		return s
	}
	if v := CheckFSComposeLintContract(clean()); len(v) != 0 {
		t.Fatalf("clean sidecar should clear the gate; got %v", v)
	}
	cases := []struct {
		name string
		mut  func(*sidecar.Sidecar)
		want string
	}{
		{"bad schema major", func(s *sidecar.Sidecar) { s.SchemaVersion = "2.0" }, "outside current major"},
		{"empty schema", func(s *sidecar.Sidecar) { s.SchemaVersion = "" }, "schema_version missing"},
		{"no digest", func(s *sidecar.Sidecar) { s.ImageDigest = "" }, "image_digest missing"},
		{"no workload", func(s *sidecar.Sidecar) { s.Workload = "" }, "workload path not set"},
		{"unreadable workload", func(s *sidecar.Sidecar) { s.Workload = "/nonexistent/csd-wl" }, "not readable"},
		{"short duration", func(s *sidecar.Sidecar) { s.DurationSeconds = 100 }, "duration_seconds 100 < 300"},
		{"low confidence", func(s *sidecar.Sidecar) { s.Confidence.Level = sidecar.ConfidenceLow }, "below moderate"},
		{"empty confidence", func(s *sidecar.Sidecar) { s.Confidence.Level = "" }, "confidence.level not set"},
		{"drop rate", func(s *sidecar.Sidecar) { s.TraceHealth.DropRate = 0.02 }, "drop_rate"},
		{"replica disagreement", func(s *sidecar.Sidecar) { s.Target.ReplicaWritePathDisagreement = []string{"/x"} }, "replica_write_path_disagreement non-empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := clean()
			tc.mut(s)
			found := false
			for _, msg := range CheckFSComposeLintContract(s) {
				if strings.Contains(msg, tc.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("expected a violation containing %q; got %v", tc.want, CheckFSComposeLintContract(s))
			}
		})
	}
}
