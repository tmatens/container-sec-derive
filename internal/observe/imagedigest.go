// Image-digest attribution: pin the observed image's content digest onto the
// sidecar so a derived profile records the exact `<repo>@sha256:...` it was
// validated against. This is observer-agnostic — every observer that emits a
// profile (caps, fs, devices, capadd, privileged) needs it — so it lives here in
// internal/observe rather than in any one observer package (#286). caps's own
// entrypoint cross-check reuses PickRepoDigest via the exported name.
package observe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// inspectableImageRef reads the targeted container's image ID (always
// resolvable) instead. No-op when fixtureMode is set (no live runtime) or when a
// digest was already attributed. A lookup failure is non-fatal: the profile
// stays un-pinned and the compose-lint contract flags the missing digest.
func PopulateImageDigest(s *sidecar.Sidecar, container, image, runtimeBin string, fixtureMode bool, stderrSink io.Writer) {
	if fixtureMode || s.ImageDigest != "" {
		return
	}
	if runtimeBin == "" {
		runtimeBin = "docker"
	}
	ctx, cancel := context.WithTimeout(context.Background(), InspectDefaultTimeout)
	defer cancel()
	ref := inspectableImageRef(ctx, container, image, s.Image, runtimeBin)
	if ref == "" {
		return
	}
	digests, err := inspectRepoDigests(ctx, ref, runtimeBin)
	if err != nil {
		if stderrSink != nil {
			fmt.Fprintf(stderrSink, "csd: image-digest lookup unavailable: %v\n", err)
		}
		return
	}
	s.ImageDigest = PickRepoDigest(s.Image, digests)
}

// inspectableImageRef returns an image reference `<runtime> inspect` can resolve
// for the observed target. The name attributed from the ig event stream is a
// bare repo with no local tag; when a --container was targeted we read the
// container's image ID (always inspectable), a --image selector is used as
// given, and the observed name is the last resort.
func inspectableImageRef(ctx context.Context, container, image, observed, runtimeBin string) string {
	if container != "" {
		out, err := exec.CommandContext(ctx, runtimeBin, "inspect", "--format", "{{.Image}}", "--", container).Output()
		if err == nil {
			if id := strings.TrimSpace(string(out)); id != "" {
				return id
			}
		}
	}
	if image != "" {
		return image
	}
	return observed
}

// inspectRepoDigests returns the image's RepoDigests ("<repo>@sha256:...", the
// pushed content digests) for a resolvable ref. Lighter than inspectEntrypoint
// (no history call) because the digest path needs only this one field.
func inspectRepoDigests(ctx context.Context, ref, runtimeBin string) ([]string, error) {
	out, err := exec.CommandContext(ctx, runtimeBin, "inspect", "--format", "{{json .RepoDigests}}", "--", ref).Output()
	if err != nil {
		return nil, fmt.Errorf("%s inspect %s: %w", runtimeBin, ref, err)
	}
	var digests []string
	if err := json.Unmarshal(bytes.TrimSpace(out), &digests); err != nil {
		return nil, fmt.Errorf("parse repo digests: %w", err)
	}
	return digests, nil
}

// PickRepoDigest returns the bare "sha256:..." digest from repoDigests
// whose repo prefix matches imageRef's repo (everything before the tag
// or @-digest). Returns "" when no digest matches; callers leave
// Sidecar.ImageDigest empty in that case rather than guess at a wrong
// repo's digest.
//
// `docker inspect` formats RepoDigests entries as "<repo>@sha256:...".
// We strip the "<repo>@" prefix so the value lines up with the format
// the compose-lint contribution flow expects (`validated_image:
// postgres:16@sha256:...` is built by appending "@" + ImageDigest).
//
// Both sides are compared in canonical registry/namespace/name form:
// RepoDigests entries elide the docker.io default (`netdata/netdata@...`)
// while the attributed image name may carry it (`docker.io/netdata/netdata`),
// and a literal comparison left every registry-qualified target un-pinned.
func PickRepoDigest(imageRef string, repoDigests []string) string {
	repo := imageRef
	if at := strings.Index(repo, "@"); at >= 0 {
		repo = repo[:at]
	}
	// A tag is a ':' in the final path segment, so a registry port
	// (localhost:5000/foo) is left intact.
	slash := strings.LastIndex(repo, "/")
	if col := strings.LastIndex(repo[slash+1:], ":"); col >= 0 {
		repo = repo[:slash+1+col]
	}
	repo = canonicalRepo(repo)
	for _, d := range repoDigests {
		i := strings.Index(d, "@")
		if i < 0 {
			continue
		}
		if canonicalRepo(d[:i]) == repo {
			return d[i+1:]
		}
	}
	return ""
}

// canonicalRepo expands a repository reference (no tag/digest) to its
// canonical registry/namespace/name: `postgres` -> docker.io/library/postgres,
// `netdata/netdata` -> docker.io/netdata/netdata, explicit registries
// (lscr.io/..., localhost:5000/...) pass through. Twin of the format
// package's normalizeRepository (which mirrors compose-lint's
// normalize_repository); duplicated because observe cannot import format
// sideways — keep the two in sync.
func canonicalRepo(name string) string {
	if name == "" {
		return name
	}
	first, rest, hasSlash := strings.Cut(name, "/")
	var registry, path string
	if hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		registry, path = strings.ToLower(first), rest
	} else {
		registry, path = "docker.io", name
	}
	if registry == "docker.io" && !strings.Contains(path, "/") {
		path = "library/" + path
	}
	return registry + "/" + path
}
