package format

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestWriteFSDockerRun(t *testing.T) {
	var b bytes.Buffer
	rec := sidecar.FSRecommendation{ReadOnly: true, TmpfsPaths: []string{"/var/log/postgresql", "/var/run/postgresql"}}
	if err := WriteFSDockerRun(&b, rec); err != nil {
		t.Fatal(err)
	}
	want := "--read-only --tmpfs /var/log/postgresql --tmpfs /var/run/postgresql\n"
	if b.String() != want {
		t.Errorf("got %q, want %q", b.String(), want)
	}

	b.Reset()
	if err := WriteFSDockerRun(&b, sidecar.FSRecommendation{ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
	if b.String() != "--read-only\n" {
		t.Errorf("empty tmpfs: got %q, want %q", b.String(), "--read-only\n")
	}
}

func TestK8sVolumeName(t *testing.T) {
	cases := map[string]string{
		"/var/log/postgresql": "writable-var-log-postgresql",
		"/tmp":                "writable-tmp",
		"/var/run/":           "writable-var-run",
		"/a/b.c/d":            "writable-a-b-c-d",
	}
	for in, want := range cases {
		if got := k8sVolumeName(in); got != want {
			t.Errorf("k8sVolumeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteFSK8s(t *testing.T) {
	var b bytes.Buffer
	rec := sidecar.FSRecommendation{ReadOnly: true, TmpfsPaths: []string{"/var/log/postgresql", "/var/run/postgresql"}}
	if err := WriteFSK8s(&b, rec); err != nil {
		t.Fatal(err)
	}
	want := "securityContext:\n" +
		"  readOnlyRootFilesystem: true\n" +
		"# in-memory scratch for the writable paths a read-only rootfs still needs\n" +
		"volumeMounts:\n" +
		"  - name: writable-var-log-postgresql\n" +
		"    mountPath: /var/log/postgresql\n" +
		"  - name: writable-var-run-postgresql\n" +
		"    mountPath: /var/run/postgresql\n" +
		"volumes:\n" +
		"  - name: writable-var-log-postgresql\n" +
		"    emptyDir:\n" +
		"      medium: Memory\n" +
		"  - name: writable-var-run-postgresql\n" +
		"    emptyDir:\n" +
		"      medium: Memory\n"
	if b.String() != want {
		t.Errorf("k8s output mismatch:\ngot:\n%s\nwant:\n%s", b.String(), want)
	}

	// No tmpfs candidates → securityContext only.
	b.Reset()
	if err := WriteFSK8s(&b, sidecar.FSRecommendation{ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
	if b.String() != "securityContext:\n  readOnlyRootFilesystem: true\n" {
		t.Errorf("empty tmpfs k8s: got %q", b.String())
	}
}

func TestWriteFSOCI(t *testing.T) {
	var b bytes.Buffer
	rec := sidecar.FSRecommendation{ReadOnly: true, TmpfsPaths: []string{"/var/log/postgresql", "/var/run/postgresql"}}
	if err := WriteFSOCI(&b, rec); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Root struct {
			Readonly bool `json:"readonly"`
		} `json:"root"`
		Mounts []struct {
			Destination string   `json:"destination"`
			Type        string   `json:"type"`
			Source      string   `json:"source"`
			Options     []string `json:"options"`
		} `json:"mounts"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("OCI output not valid JSON: %v\n%s", err, b.String())
	}
	if !got.Root.Readonly {
		t.Error("root.readonly = false, want true")
	}
	if len(got.Mounts) != 2 {
		t.Fatalf("mounts len = %d, want 2", len(got.Mounts))
	}
	if got.Mounts[0].Destination != "/var/log/postgresql" || got.Mounts[0].Type != "tmpfs" {
		t.Errorf("mount[0] = %+v", got.Mounts[0])
	}

	// No tmpfs candidates → mounts is an explicit empty array, not null.
	b.Reset()
	if err := WriteFSOCI(&b, sidecar.FSRecommendation{ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"mounts": []`) {
		t.Errorf("expected explicit empty mounts array, got:\n%s", b.String())
	}
}

// TestRun_ObserveFSFormats exercises each newly-wired fs formatter end-to-end
// through run() against the committed fixtures.
