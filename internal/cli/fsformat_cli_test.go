package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
)

const fsPatchCompose = `services:
  web:
    image: nginx
    ports:
      - "80:80"
`

func TestRun_ObserveFSFormats(t *testing.T) {
	base := []string{
		"--observe", "fs",
		"--fixture", "../../testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		"--mounts-fixture", "../../testdata/postgres/mounts.json",
		"--container", "postgres-1",
	}
	cases := map[string]string{
		"docker-run": "--read-only --tmpfs /var/log/postgresql --tmpfs /var/run/postgresql",
		"k8s":        "readOnlyRootFilesystem: true",
		"oci":        `"readonly": true`,
	}
	for format, want := range cases {
		var out, errBuf bytes.Buffer
		args := append(append([]string{}, base...), "--format", format)
		if err := Run(args, &out, &errBuf); err != nil {
			t.Fatalf("format %s: run: %v (stderr: %s)", format, err, errBuf.String())
		}
		if !strings.Contains(out.String(), want) {
			t.Errorf("format %s: output missing %q:\n%s", format, want, out.String())
		}
	}
}

func TestRun_ObserveFSComposePatchAndProfile(t *testing.T) {
	dir := t.TempDir()
	composeFile := filepath.Join(dir, "compose.yml")
	if err := os.WriteFile(composeFile, []byte(fsPatchCompose), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{
		"--observe", "fs",
		"--fixture", "../../testdata/ig-versions/v0.51.0/trace_open_sample.ndjson",
		"--mounts-fixture", "../../testdata/postgres/mounts.json",
		"--container", "postgres-1",
	}

	// compose-patch
	var out, errBuf bytes.Buffer
	args := append(append([]string{}, base...), "--format", "compose-patch", "--compose-in", composeFile, "--service", "web")
	if err := Run(args, &out, &errBuf); err != nil {
		t.Fatalf("compose-patch run: %v (stderr: %s)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), "+    read_only: true") {
		t.Errorf("compose-patch output unexpected:\n%s", out.String())
	}

	// compose-patch without --service is EX_USAGE
	out.Reset()
	errBuf.Reset()
	bad := append(append([]string{}, base...), "--format", "compose-patch", "--compose-in", composeFile)
	if exit.CodeFor(Run(bad, &out, &errBuf)) != exit.Usage {
		t.Error("compose-patch without --service should be EX_USAGE")
	}

	// compose-lint-profile (sparse fixture → contract fails; --allow-exploratory emits)
	out.Reset()
	errBuf.Reset()
	prof := append(append([]string{}, base...), "--format", "compose-lint-profile", "--allow-exploratory")
	if err := Run(prof, &out, &errBuf); err != nil {
		t.Fatalf("exploratory profile run: %v (stderr: %s)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), "read_only: true") || !strings.Contains(out.String(), "status: exploratory") {
		t.Errorf("exploratory profile output unexpected:\n%s", out.String())
	}
}
