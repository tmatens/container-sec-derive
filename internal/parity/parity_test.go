// Package parity holds the v1 compose-lint parity cross-check gate.
//
// PLAN.md "v1 success criteria" > Correctness requires an INDEPENDENT
// cross-check: csd's bisected postgres cap set must agree with compose-lint's
// curated profile, or ship a documented divergence rationale. That criterion is
// weighted equal to bisection (see PLAN.md "Validation methodology"), yet
// nothing mechanically enforced it — the two artifacts could silently drift
// apart. This test is that enforcement (issue #294).
//
// It reads each committed ground_truth.json and the pinned curated mirror in
// testdata/parity/compose-lint-profiles.json, computes the set difference, and
// fails unless it EXACTLY equals the accepted_delta recorded alongside its
// rationale. Re-bisecting an image, or compose-lint changing a curated set,
// breaks this gate until docs/known-deltas.md and the manifest are reconciled.
//
// It runs in the plain `go test ./...` lane: no Docker, no BPF, no network.
package parity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// manifest mirrors testdata/parity/compose-lint-profiles.json.
type manifest struct {
	Profiles []profile `json:"profiles"`
}

type profile struct {
	Image         string   `json:"image"`
	GroundTruth   string   `json:"ground_truth"`
	CuratedCaps   []string `json:"curated_caps"`
	AcceptedDelta delta    `json:"accepted_delta"`
}

type delta struct {
	MissingFromBisected []string `json:"missing_from_bisected"`
	ExtraInBisected     []string `json:"extra_in_bisected"`
	Disposition         string   `json:"disposition"`
	Rationale           string   `json:"rationale"`
}

type groundTruth struct {
	Caps []string `json:"caps"`
}

// repoRoot walks up from the test's working directory to the module root
// (the directory holding go.mod), so testdata paths resolve regardless of
// where `go test` is invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (no go.mod found walking up)")
		}
		dir = parent
	}
}

// diff returns the two directional set differences (curated \ bisected) and
// (bisected \ curated), each sorted, so comparisons are order-independent.
func diff(curated, bisected []string) (missing, extra []string) {
	cset := map[string]bool{}
	for _, c := range curated {
		cset[c] = true
	}
	bset := map[string]bool{}
	for _, c := range bisected {
		bset[c] = true
	}
	for c := range cset {
		if !bset[c] {
			missing = append(missing, c)
		}
	}
	for c := range bset {
		if !cset[c] {
			extra = append(extra, c)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

func norm(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func equalSets(a, b []string) bool {
	a, b = norm(a), norm(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestComposeLintParity is the v1 independent cross-check gate (#294).
func TestComposeLintParity(t *testing.T) {
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "testdata", "parity", "compose-lint-profiles.json"))
	if err != nil {
		t.Fatalf("read parity manifest: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse parity manifest: %v", err)
	}
	if len(m.Profiles) == 0 {
		t.Fatal("parity manifest has no profiles: the gate would be a no-op")
	}

	for _, p := range m.Profiles {
		t.Run(p.Image, func(t *testing.T) {
			gtPath := filepath.Join(root, filepath.FromSlash(p.GroundTruth))
			gtRaw, err := os.ReadFile(gtPath)
			if err != nil {
				t.Fatalf("read ground truth %s: %v", p.GroundTruth, err)
			}
			var gt groundTruth
			if err := json.Unmarshal(gtRaw, &gt); err != nil {
				t.Fatalf("parse ground truth %s: %v", p.GroundTruth, err)
			}
			if len(p.CuratedCaps) == 0 {
				t.Fatalf("%s: curated_caps is empty; nothing to cross-check against", p.Image)
			}

			gotMissing, gotExtra := diff(p.CuratedCaps, gt.Caps)

			nonEmpty := len(gotMissing) > 0 || len(gotExtra) > 0

			if !equalSets(gotMissing, p.AcceptedDelta.MissingFromBisected) ||
				!equalSets(gotExtra, p.AcceptedDelta.ExtraInBisected) {
				t.Errorf(`parity cross-check drift for %s.

The independent compose-lint cross-check (PLAN.md v1 success criteria, #294) no
longer matches the accepted delta. Something changed on one side without the
rationale being updated on the other.

  bisected (%s):        %v
  curated  (compose-lint): %v

  actual delta   missing_from_bisected=%v extra_in_bisected=%v
  accepted delta missing_from_bisected=%v extra_in_bisected=%v

To resolve: reconcile testdata/parity/compose-lint-profiles.json (accepted_delta
+ curated_caps) with the re-bisected ground truth AND record the cause in
docs/known-deltas.md, in the same commit. "The tool is non-deterministic" is not
an acceptable cause.`,
					p.Image, p.GroundTruth, norm(gt.Caps), norm(p.CuratedCaps),
					gotMissing, gotExtra,
					norm(p.AcceptedDelta.MissingFromBisected), norm(p.AcceptedDelta.ExtraInBisected))
				return
			}

			// A non-empty accepted delta must ship a rationale that points at a
			// real file, so the divergence can never be waved through silently.
			if nonEmpty {
				if strings.TrimSpace(p.AcceptedDelta.Rationale) == "" {
					t.Errorf("%s: divergence accepted but rationale is empty", p.Image)
					return
				}
				ratFile := strings.TrimSpace(strings.SplitN(p.AcceptedDelta.Rationale, "—", 2)[0])
				if ratFile == "" {
					t.Errorf("%s: rationale does not name a file: %q", p.Image, p.AcceptedDelta.Rationale)
					return
				}
				if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(ratFile))); err != nil {
					t.Errorf("%s: rationale names %q but it is not readable: %v", p.Image, ratFile, err)
				}
			}
		})
	}
}
