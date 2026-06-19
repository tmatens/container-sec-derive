package caps

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/obstest"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// deriveExpectedCaps is pure over entrypointInspection; table tests cover
// each PLAN.md §Workload coverage item 1 heuristic row plus empty/negative
// cases. Setcap extraction from history is exercised in its own test.
func TestDeriveExpectedCaps_HeuristicTable(t *testing.T) {
	cases := []struct {
		name     string
		insp     entrypointInspection
		wantCaps []string
	}{
		{
			name:     "empty inspection produces no expected caps",
			insp:     entrypointInspection{},
			wantCaps: []string{},
		},
		{
			name: "chown in entrypoint expects CHOWN/FOWNER/DAC_OVERRIDE",
			insp: entrypointInspection{
				Entrypoint: []string{"chown", "-R", "postgres:postgres", "/var/lib/postgresql"},
			},
			wantCaps: []string{"CHOWN", "DAC_OVERRIDE", "FOWNER"},
		},
		{
			name: "chmod in cmd expects CHOWN/FOWNER/DAC_OVERRIDE",
			insp: entrypointInspection{
				Cmd: []string{"sh", "-c", "chmod 600 /etc/secrets && exec app"},
			},
			wantCaps: []string{"CHOWN", "DAC_OVERRIDE", "FOWNER"},
		},
		{
			name: "gosu expects SETUID/SETGID",
			insp: entrypointInspection{
				Cmd: []string{"gosu", "appuser", "/app/server"},
			},
			wantCaps: []string{"SETGID", "SETUID"},
		},
		{
			name: "su-exec expects SETUID/SETGID",
			insp: entrypointInspection{
				Cmd: []string{"su-exec", "appuser", "/app/server"},
			},
			wantCaps: []string{"SETGID", "SETUID"},
		},
		{
			name: "setpriv expects SETUID/SETGID",
			insp: entrypointInspection{
				Entrypoint: []string{"setpriv", "--reuid=app", "--regid=app", "--init-groups", "/app/run"},
			},
			wantCaps: []string{"SETGID", "SETUID"},
		},
		{
			name: "mount expects SYS_ADMIN",
			insp: entrypointInspection{
				Cmd: []string{"sh", "-c", "mount -t proc proc /proc && exec app"},
			},
			wantCaps: []string{"SYS_ADMIN"},
		},
		{
			name: "umount expects SYS_ADMIN",
			insp: entrypointInspection{
				Cmd: []string{"sh", "-c", "umount /mnt/scratch && exec app"},
			},
			wantCaps: []string{"SYS_ADMIN"},
		},
		{
			name: "ping expects NET_RAW",
			insp: entrypointInspection{
				Cmd: []string{"ping", "-c", "1", "gateway"},
			},
			wantCaps: []string{"NET_RAW"},
		},
		{
			name: "postgres-style scripted entrypoint matches nothing (argv-only, phase A limitation)",
			insp: entrypointInspection{
				Entrypoint: []string{"docker-entrypoint.sh"},
				Cmd:        []string{"postgres"},
			},
			wantCaps: []string{},
		},
		{
			name: "multiple signals union their cap sets",
			insp: entrypointInspection{
				Cmd: []string{"sh", "-c", "chown app /var/data && exec gosu app /app/run"},
			},
			wantCaps: []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"},
		},
		{
			name: "case-insensitive: CHMOD as a literal still matches",
			insp: entrypointInspection{
				Entrypoint: []string{"CHMOD", "0600", "/etc/key"},
			},
			wantCaps: []string{"CHOWN", "DAC_OVERRIDE", "FOWNER"},
		},
		{
			name: "word boundary: `paramount` does not match `mount`",
			insp: entrypointInspection{
				Entrypoint: []string{"paramount-runner"},
			},
			wantCaps: []string{},
		},
		{
			name: "word boundary: `ichowning` does not match `chown`",
			insp: entrypointInspection{
				Entrypoint: []string{"ichowning-service"},
			},
			wantCaps: []string{},
		},
		{
			name: "setcap in history contributes its named cap",
			insp: entrypointInspection{
				HistoryLines: []string{
					"/bin/sh -c apt-get install -y libcap2-bin",
					"/bin/sh -c setcap cap_net_raw=+ep /usr/bin/ping",
				},
			},
			wantCaps: []string{"NET_RAW"},
		},
		{
			name: "setcap with comma-list extracts every cap",
			insp: entrypointInspection{
				HistoryLines: []string{
					"/bin/sh -c setcap cap_net_raw,cap_net_bind_service=+ep /usr/bin/ping",
				},
			},
			wantCaps: []string{"NET_BIND_SERVICE", "NET_RAW"},
		},
		{
			name: "line mentioning cap_* without setcap is ignored",
			insp: entrypointInspection{
				HistoryLines: []string{
					"/bin/sh -c apt-get install -y libcap2-bin && cat /etc/issue # cap_net_raw reference only",
				},
			},
			wantCaps: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := deriveExpectedCaps(tc.insp)
			if !obstest.EqualSlice(got, tc.wantCaps) {
				t.Errorf("caps = %v, want %v", got, tc.wantCaps)
			}
		})
	}
}

func TestComputeCoverageWarnings_SetDifference(t *testing.T) {
	// One signal expecting 3 caps, observed covers 1, warnings for 2.
	hits := []signalHit{
		{prose: "entrypoint references `chown`", triggeredCaps: []string{"CHOWN", "FOWNER", "DAC_OVERRIDE"}},
	}
	observed := []string{"CHOWN", "SETUID"}
	warnings := computeCoverageWarnings(hits, observed)
	if len(warnings) != 2 {
		t.Fatalf("want 2 warnings (FOWNER + DAC_OVERRIDE missing); got %d:\n%v", len(warnings), warnings)
	}
	joined := strings.Join(warnings, "\n")
	for _, cap := range []string{"FOWNER", "DAC_OVERRIDE"} {
		if !strings.Contains(joined, cap) {
			t.Errorf("missing %s warning in:\n%s", cap, joined)
		}
	}
	for _, cap := range []string{"CHOWN", "SETUID"} {
		if strings.Contains(joined, " "+cap+" was not") {
			t.Errorf("unexpected warning for covered cap %s:\n%s", cap, joined)
		}
	}
}

func TestComputeCoverageWarnings_DedupesIdenticalMessages(t *testing.T) {
	// chown and chmod both expect CHOWN; if both signals fire and CHOWN
	// is missing, each still emits its own distinct-source warning. But
	// the same (signal, cap) pair must not duplicate.
	hits := []signalHit{
		{prose: "entrypoint references `chown`", triggeredCaps: []string{"CHOWN"}},
		{prose: "entrypoint references `chown`", triggeredCaps: []string{"CHOWN"}}, // dup
		{prose: "entrypoint references `chmod`", triggeredCaps: []string{"CHOWN"}},
	}
	warnings := computeCoverageWarnings(hits, []string{})
	if len(warnings) != 2 {
		t.Errorf("expected 2 distinct warnings (chown + chmod); got %d:\n%v", len(warnings), warnings)
	}
}

func TestComputeCoverageWarnings_EmptyInputs(t *testing.T) {
	if got := computeCoverageWarnings(nil, []string{"CHOWN"}); len(got) != 0 {
		t.Errorf("nil hits should yield no warnings, got %v", got)
	}
	hits := []signalHit{{prose: "x", triggeredCaps: []string{"CHOWN"}}}
	if got := computeCoverageWarnings(hits, []string{"CHOWN"}); len(got) != 0 {
		t.Errorf("fully-covered hits should yield no warnings, got %v", got)
	}
}

func TestLoadInspectionFixture_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "insp.json")
	want := entrypointInspection{
		Image:        "postgres:16",
		Entrypoint:   []string{"docker-entrypoint.sh"},
		Cmd:          []string{"postgres"},
		HistoryLines: []string{"/bin/sh -c setcap cap_net_raw=+ep /usr/bin/ping"},
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := loadInspectionFixture(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Image != want.Image || !obstest.EqualSlice(got.Entrypoint, want.Entrypoint) ||
		!obstest.EqualSlice(got.Cmd, want.Cmd) || !obstest.EqualSlice(got.HistoryLines, want.HistoryLines) {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

func TestLoadInspectionFixture_FileMissing(t *testing.T) {
	_, err := loadInspectionFixture("/nonexistent/path/inspect.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// ApplyEntrypointCrossCheck's three inspection-source priorities:
// fixture wins, fixture-mode-without-fixture skips, and live-path-with-
// image routes through inspectEntrypoint (not exercised here because it
// needs a docker daemon; the live path is covered by the run-level
// integration tests gated on docker availability).
func TestApplyEntrypointCrossCheck_FixtureWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "insp.json")
	b, _ := json.Marshal(entrypointInspection{
		Entrypoint: []string{"chown", "-R", "app", "/data"},
	})
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := sidecar.NewSidecar()
	s.Image = "ignored-because-fixture-wins"
	s.Capabilities = []sidecar.Capability{{Name: "CHOWN"}}
	var stderrBuf bytes.Buffer
	ApplyEntrypointCrossCheck(s, path, "", false, &stderrBuf)

	if s.CrossCheckStatus != sidecar.CrossCheckStatusOK {
		t.Errorf("status = %q, want %q", s.CrossCheckStatus, sidecar.CrossCheckStatusOK)
	}
	if !obstest.EqualSlice(s.ExpectedCapsFromEntrypoint, []string{"CHOWN", "DAC_OVERRIDE", "FOWNER"}) {
		t.Errorf("expected caps = %v", s.ExpectedCapsFromEntrypoint)
	}
	// CHOWN observed; FOWNER and DAC_OVERRIDE missing.
	if len(s.CoverageWarnings) != 2 {
		t.Errorf("warnings = %v (want 2)", s.CoverageWarnings)
	}
	// Warnings should also have been echoed to stderr sink.
	if !strings.Contains(stderrBuf.String(), "coverage_warning:") {
		t.Errorf("stderr missing coverage_warning prose:\n%s", stderrBuf.String())
	}
}

func TestApplyEntrypointCrossCheck_FixtureModeSkipsSilently(t *testing.T) {
	s := sidecar.NewSidecar()
	s.Image = "postgres:16" // ignored in fixture mode without --inspect-fixture
	var stderrBuf bytes.Buffer
	ApplyEntrypointCrossCheck(s, "", "", true, &stderrBuf)

	if s.CrossCheckStatus != "" {
		t.Errorf("fixture-mode skip should leave status empty, got %q", s.CrossCheckStatus)
	}
	if len(s.ExpectedCapsFromEntrypoint) != 0 {
		t.Errorf("expected caps should be empty on skip, got %v", s.ExpectedCapsFromEntrypoint)
	}
	if len(s.CoverageWarnings) != 0 {
		t.Errorf("warnings should be empty on skip, got %v", s.CoverageWarnings)
	}
	if stderrBuf.Len() != 0 {
		t.Errorf("stderr should be silent on skip:\n%s", stderrBuf.String())
	}
}

func TestApplyEntrypointCrossCheck_NoImageInLiveModeRecordsReason(t *testing.T) {
	s := sidecar.NewSidecar()
	// No Image, not fixture mode, no inspect-fixture.
	ApplyEntrypointCrossCheck(s, "", "", false, nil)
	if s.CrossCheckStatus == "" || s.CrossCheckStatus == sidecar.CrossCheckStatusOK {
		t.Errorf("expected non-ok reason for live mode without image, got %q", s.CrossCheckStatus)
	}
}

func TestApplyEntrypointCrossCheck_InspectFixtureUnreadable(t *testing.T) {
	s := sidecar.NewSidecar()
	s.Image = "postgres:16"
	ApplyEntrypointCrossCheck(s, "/nonexistent/inspect.json", "", false, nil)
	if s.CrossCheckStatus == sidecar.CrossCheckStatusOK || s.CrossCheckStatus == "" {
		t.Errorf("missing fixture should yield unavailable reason; got %q", s.CrossCheckStatus)
	}
	if !strings.Contains(s.CrossCheckStatus, "fixture") {
		t.Errorf("reason should mention fixture; got %q", s.CrossCheckStatus)
	}
}

// Regression: computeCoverageWarnings must never return nil, because
// assigning nil to s.CoverageWarnings overwrites the pre-initialized
// empty slice and serializes as `null` -- a schema-contract break per
// PLAN.md §Output schema (consumers reject null arrays as schema drift).
func TestComputeCoverageWarnings_EmptyResultIsNonNilSlice(t *testing.T) {
	got := computeCoverageWarnings(nil, nil)
	if got == nil {
		t.Fatal("nil return overwrites Sidecar's empty-slice init; serializes as null")
	}
	if len(got) != 0 {
		t.Errorf("want empty (len 0), got %d entries", len(got))
	}
}

func TestPickRepoDigest_MatchesByRepo(t *testing.T) {
	cases := []struct {
		name     string
		imageRef string
		digests  []string
		want     string
	}{
		{
			name:     "tagged ref matches by repo prefix",
			imageRef: "postgres:16",
			digests:  []string{"postgres@sha256:aaaaaaaaaaaa"},
			want:     "sha256:aaaaaaaaaaaa",
		},
		{
			name:     "registry-qualified ref matches its qualified digest entry",
			imageRef: "docker.io/library/postgres:16",
			digests: []string{
				"postgres@sha256:bbbbbbbbbbbb",
				"docker.io/library/postgres@sha256:cccccccccccc",
			},
			want: "sha256:cccccccccccc",
		},
		{
			name:     "ref already pinned by digest still matches by repo",
			imageRef: "postgres:16@sha256:dddddddddddd",
			digests:  []string{"postgres@sha256:dddddddddddd"},
			want:     "sha256:dddddddddddd",
		},
		{
			name:     "no matching repo returns empty",
			imageRef: "postgres:16",
			digests:  []string{"redis@sha256:eeeeeeeeeeee"},
			want:     "",
		},
		{
			name:     "empty repo digests returns empty",
			imageRef: "postgres:16",
			digests:  nil,
			want:     "",
		},
		{
			name:     "malformed digest entry without @ is skipped",
			imageRef: "postgres:16",
			digests:  []string{"postgres-no-digest", "postgres@sha256:ffffffffffff"},
			want:     "sha256:ffffffffffff",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pickRepoDigest(tc.imageRef, tc.digests); got != tc.want {
				t.Errorf("pickRepoDigest(%q, %v) = %q, want %q", tc.imageRef, tc.digests, got, tc.want)
			}
		})
	}
}

func TestApplyEntrypointCrossCheck_PromotesRepoDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "insp.json")
	b, _ := json.Marshal(entrypointInspection{
		Image:       "postgres:16",
		Entrypoint:  []string{"docker-entrypoint.sh"},
		Cmd:         []string{"postgres"},
		RepoDigests: []string{"postgres@sha256:1111111111111111111111111111111111111111111111111111111111111111"},
	})
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := sidecar.NewSidecar()
	s.Image = "postgres:16"
	ApplyEntrypointCrossCheck(s, path, "", false, nil)
	if s.CrossCheckStatus != sidecar.CrossCheckStatusOK {
		t.Fatalf("status = %q, want %q", s.CrossCheckStatus, sidecar.CrossCheckStatusOK)
	}
	want := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	if s.ImageDigest != want {
		t.Errorf("ImageDigest = %q, want %q", s.ImageDigest, want)
	}
}

// Pre-populated digest wins over inspection's view: a future --digest
// flag (or any caller that already attributed a digest) must not be
// overwritten by the cross-check.
func TestApplyEntrypointCrossCheck_PreservesExistingDigest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "insp.json")
	b, _ := json.Marshal(entrypointInspection{
		Image:       "postgres:16",
		RepoDigests: []string{"postgres@sha256:2222222222222222222222222222222222222222222222222222222222222222"},
	})
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := sidecar.NewSidecar()
	s.Image = "postgres:16"
	s.ImageDigest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	ApplyEntrypointCrossCheck(s, path, "", false, nil)
	if s.ImageDigest != "sha256:9999999999999999999999999999999999999999999999999999999999999999" {
		t.Errorf("pre-populated digest overwritten: got %q", s.ImageDigest)
	}
}

func TestSetcapCapsFromHistory_IgnoresNonSetcapMentions(t *testing.T) {
	lines := []string{
		"/bin/sh -c apt-get install libcap2-bin",                // no setcap
		"/bin/sh -c getcap cap_net_raw /usr/bin/ping",           // getcap, not setcap
		"/bin/sh -c setcap cap_net_admin=+ep /usr/sbin/adm-bin", // match
		"/bin/sh -c SETCAP CAP_SYS_TIME=+ep /usr/bin/time-bin",  // case-insensitive
	}
	got := setcapCapsFromHistory(lines)
	want := []string{"NET_ADMIN", "SYS_TIME"}
	if !obstest.EqualSlice(got, want) {
		t.Errorf("setcap extraction = %v, want %v", got, want)
	}
}
