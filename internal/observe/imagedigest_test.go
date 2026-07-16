package observe

import (
	"io"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

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
				"redis@sha256:bbbbbbbbbbbb",
				"docker.io/library/postgres@sha256:cccccccccccc",
			},
			want: "sha256:cccccccccccc",
		},
		{
			// Regression: docker reports RepoDigests with the docker.io
			// default elided, while the attributed image name may carry it.
			// A literal repo comparison left every registry-qualified target
			// un-pinned (the netdata capadd derivation shipped no digest).
			name:     "registry-qualified ref matches an unqualified digest entry",
			imageRef: "docker.io/netdata/netdata:v2.10.3",
			digests:  []string{"netdata/netdata@sha256:bbbbbbbbbbbb"},
			want:     "sha256:bbbbbbbbbbbb",
		},
		{
			name:     "bare library ref matches an unqualified digest entry",
			imageRef: "docker.io/library/postgres:16",
			digests:  []string{"postgres@sha256:cccccccccccc"},
			want:     "sha256:cccccccccccc",
		},
		{
			name:     "explicit non-default registry must still match exactly",
			imageRef: "lscr.io/linuxserver/radarr:latest",
			digests:  []string{"linuxserver/radarr@sha256:bbbbbbbbbbbb"},
			want:     "",
		},
		{
			name:     "registry port is not mistaken for a tag",
			imageRef: "localhost:5000/foo",
			digests:  []string{"localhost:5000/foo@sha256:abcdefabcdef"},
			want:     "sha256:abcdefabcdef",
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
			if got := PickRepoDigest(tc.imageRef, tc.digests); got != tc.want {
				t.Errorf("PickRepoDigest(%q, %v) = %q, want %q", tc.imageRef, tc.digests, got, tc.want)
			}
		})
	}
}

// TestPopulateImageDigest_Guards covers the hermetic no-op guards — the live
// docker-inspect path is exercised by scripts/smoke_fs.sh, not here. These
// guards must return before any subprocess so a fixture run (no daemon) and an
// already-pinned sidecar are untouched.
func TestPopulateImageDigest_Guards(t *testing.T) {
	t.Run("fixture mode is a no-op even with a container", func(t *testing.T) {
		s := sidecar.NewSidecar()
		s.Image = "postgres"
		PopulateImageDigest(s, "some-container", "", "docker", true /*fixtureMode*/, io.Discard)
		if s.ImageDigest != "" {
			t.Errorf("fixture mode must not set ImageDigest, got %q", s.ImageDigest)
		}
	})
	t.Run("already-pinned digest is preserved (no lookup)", func(t *testing.T) {
		s := sidecar.NewSidecar()
		s.Image = "postgres"
		s.ImageDigest = "sha256:" + strings.Repeat("a", 64)
		// container set + fixtureMode false would hit docker, but the
		// already-set guard returns first — so this stays hermetic.
		PopulateImageDigest(s, "some-container", "", "docker", false, io.Discard)
		if s.ImageDigest != "sha256:"+strings.Repeat("a", 64) {
			t.Errorf("already-set ImageDigest must be preserved, got %q", s.ImageDigest)
		}
	})
}
