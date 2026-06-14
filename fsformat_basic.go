package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// The v0.2 fs formatters below mirror the cap formatters (docker_run.go /
// k8s.go / oci.go) but express the read-only-filesystem recommendation rather
// than a cap set. All three consume fsRecommendation directly (like
// writeFSCompose) and emit `read_only`-equivalent rootfs locking plus a tmpfs
// mount per TmpfsPaths entry. VolumeCovered paths are deliberately NOT emitted:
// they are already satisfied by the user's existing bind/volume mounts, which
// stay writable under a read-only rootfs — only the incidental rootfs writes
// need tmpfs. Empty TmpfsPaths yields the cleanest valid shape (rootfs locked,
// no tmpfs), matching writeFSCompose's elision.

// writeFSDockerRun emits a `docker run` flag string realizing the fs
// recommendation: `--read-only` plus one `--tmpfs <path>` per tmpfs candidate,
// space-separated on a single line for pasting into an existing `docker run`.
func writeFSDockerRun(w io.Writer, rec fsRecommendation) error {
	parts := []string{"--read-only"}
	for _, p := range rec.TmpfsPaths {
		parts = append(parts, "--tmpfs "+p)
	}
	_, err := fmt.Fprintln(w, strings.Join(parts, " "))
	return err
}

// writeFSK8s emits a Kubernetes block realizing the fs recommendation:
// `securityContext.readOnlyRootFilesystem: true`, plus an in-memory
// (`emptyDir.medium: Memory`) volume and matching volumeMount per tmpfs
// candidate — the idiomatic k8s equivalent of a tmpfs, since a read-only
// root filesystem still needs writable scratch for incidental paths. Output is
// two-space block style for pasting under a container spec. When there are no
// tmpfs candidates, only the securityContext stanza is emitted.
func writeFSK8s(w io.Writer, rec fsRecommendation) error {
	if _, err := fmt.Fprintln(w, "securityContext:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  readOnlyRootFilesystem: true"); err != nil {
		return err
	}
	if len(rec.TmpfsPaths) == 0 {
		return nil
	}
	names := make([]string, len(rec.TmpfsPaths))
	for i, p := range rec.TmpfsPaths {
		names[i] = k8sVolumeName(p)
	}
	if _, err := fmt.Fprintln(w, "# in-memory scratch for the writable paths a read-only rootfs still needs"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "volumeMounts:"); err != nil {
		return err
	}
	for i, p := range rec.TmpfsPaths {
		if _, err := fmt.Fprintf(w, "  - name: %s\n    mountPath: %s\n", names[i], p); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "volumes:"); err != nil {
		return err
	}
	for _, n := range names {
		if _, err := fmt.Fprintf(w, "  - name: %s\n    emptyDir:\n      medium: Memory\n", n); err != nil {
			return err
		}
	}
	return nil
}

// k8sVolumeName derives a stable DNS-1123 volume name from a tmpfs path:
// "/var/log/postgresql" -> "writable-var-log-postgresql". Non-alphanumeric
// runs collapse to a single dash; the result is lowercased and dash-trimmed.
// The "writable-" prefix guarantees a leading alphanumeric (DNS-1123 requires
// it) and namespaces these against the user's own volumes.
func k8sVolumeName(p string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(p) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return "writable-" + strings.Trim(b.String(), "-")
}

// writeFSOCI emits an OCI runtime spec snippet realizing the fs recommendation:
// `root.readonly: true` plus a tmpfs mount per tmpfs candidate. Users paste
// into an OCI bundle's config.json or merge it against an existing config.
// `mounts` is always present (an explicit empty array when there are no tmpfs
// candidates) so a merge tool overwrites any templated mounts to the
// minimum-privilege shape, mirroring writeOCI's explicit-empty arrays.
func writeFSOCI(w io.Writer, rec fsRecommendation) error {
	type ociMount struct {
		Destination string   `json:"destination"`
		Type        string   `json:"type"`
		Source      string   `json:"source"`
		Options     []string `json:"options"`
	}
	snippet := struct {
		Root struct {
			Readonly bool `json:"readonly"`
		} `json:"root"`
		Mounts []ociMount `json:"mounts"`
	}{}
	snippet.Root.Readonly = true
	snippet.Mounts = []ociMount{}
	for _, p := range rec.TmpfsPaths {
		snippet.Mounts = append(snippet.Mounts, ociMount{
			Destination: p,
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "nodev", "noexec"},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(snippet)
}
