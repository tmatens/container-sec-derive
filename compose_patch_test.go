package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// helperSidecarWithCaps returns a Sidecar carrying caps in the order
// supplied; matches what aggregate() produces for downstream formatters.
func helperSidecarWithCaps(caps ...string) *Sidecar {
	s := NewSidecar()
	for _, c := range caps {
		s.Capabilities = append(s.Capabilities, Capability{Name: c})
	}
	return s
}

func TestComposePatch_RewritesExistingCapBlocks(t *testing.T) {
	in := []byte(`services:
  app:
    image: postgres:16
    cap_drop:
      - SETUID
    cap_add:
      - CHOWN
      - DAC_OVERRIDE
    environment:
      FOO: bar
`)
	s := helperSidecarWithCaps("FOWNER", "SETGID")
	var buf bytes.Buffer
	if err := writeComposePatch(&buf, s, in, "compose.yaml", "app"); err != nil {
		t.Fatalf("writeComposePatch: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"--- a/compose.yaml",
		"+++ b/compose.yaml",
		"+    cap_drop:",
		"+      - ALL",
		"+    cap_add:",
		"+      - FOWNER",
		"+      - SETGID",
		"-    cap_drop:",
		"-      - SETUID",
		"-    cap_add:",
		"-      - CHOWN",
		"-      - DAC_OVERRIDE",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("diff missing %q\nfull diff:\n%s", want, got)
		}
	}
	// Other body keys must survive — no `-` line for image: or environment:.
	for _, mustKeep := range []string{"image: postgres:16", "environment:", "FOO: bar"} {
		if strings.Contains(got, "-    "+mustKeep) || strings.Contains(got, "-      "+mustKeep) {
			t.Errorf("diff incorrectly removed %q\nfull diff:\n%s", mustKeep, got)
		}
	}
}

func TestComposePatch_InsertsWhenAbsent(t *testing.T) {
	in := []byte(`services:
  app:
    image: postgres:16
    environment:
      FOO: bar
`)
	s := helperSidecarWithCaps("CHOWN")
	var buf bytes.Buffer
	if err := writeComposePatch(&buf, s, in, "compose.yaml", "app"); err != nil {
		t.Fatalf("writeComposePatch: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"+    cap_drop:",
		"+      - ALL",
		"+    cap_add:",
		"+      - CHOWN",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("diff missing %q\nfull diff:\n%s", want, got)
		}
	}
	if strings.Contains(got, "-    image:") || strings.Contains(got, "-    environment:") {
		t.Errorf("diff removed an unrelated body line:\n%s", got)
	}
}

func TestComposePatch_EmptyCapSetOmitsCapAdd(t *testing.T) {
	in := []byte(`services:
  app:
    image: postgres:16
    cap_add:
      - CHOWN
`)
	s := helperSidecarWithCaps()
	var buf bytes.Buffer
	if err := writeComposePatch(&buf, s, in, "compose.yaml", "app"); err != nil {
		t.Fatalf("writeComposePatch: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "+    cap_drop:") || !strings.Contains(got, "+      - ALL") {
		t.Errorf("missing cap_drop/ALL:\n%s", got)
	}
	if strings.Contains(got, "+    cap_add:") {
		t.Errorf("empty cap set must not emit cap_add:\n%s", got)
	}
	// Old cap_add block is removed.
	if !strings.Contains(got, "-    cap_add:") || !strings.Contains(got, "-      - CHOWN") {
		t.Errorf("expected old cap_add removed:\n%s", got)
	}
}

func TestComposePatch_NoOpWhenAlreadyMatches(t *testing.T) {
	in := []byte(`services:
  app:
    image: postgres:16
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
`)
	s := helperSidecarWithCaps("CHOWN")
	var buf bytes.Buffer
	if err := writeComposePatch(&buf, s, in, "compose.yaml", "app"); err != nil {
		t.Fatalf("writeComposePatch: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no-op (empty diff) when caps already match; got:\n%s", buf.String())
	}
}

func TestComposePatch_ServiceNotFoundErrors(t *testing.T) {
	in := []byte(`services:
  app:
    image: postgres:16
`)
	s := helperSidecarWithCaps("CHOWN")
	var buf bytes.Buffer
	err := writeComposePatch(&buf, s, in, "compose.yaml", "missing")
	if err == nil || !strings.Contains(err.Error(), `"missing"`) {
		t.Errorf("expected service-not-found error, got: %v", err)
	}
}

func TestComposePatch_NoServicesBlockErrors(t *testing.T) {
	in := []byte(`version: "3"
volumes: {}
`)
	s := helperSidecarWithCaps("CHOWN")
	var buf bytes.Buffer
	err := writeComposePatch(&buf, s, in, "compose.yaml", "app")
	if err == nil || !strings.Contains(err.Error(), "services:") {
		t.Errorf("expected services-block-missing error, got: %v", err)
	}
}

func TestComposePatch_EmptyServiceArgErrors(t *testing.T) {
	s := helperSidecarWithCaps("CHOWN")
	var buf bytes.Buffer
	err := writeComposePatch(&buf, s, []byte("services:\n  app:\n    image: x\n"), "compose.yaml", "")
	if err == nil || !strings.Contains(err.Error(), "--service") {
		t.Errorf("expected --service required error, got: %v", err)
	}
}

func TestComposePatch_HunkHeaderIsValid(t *testing.T) {
	in := []byte(`services:
  app:
    image: postgres:16
    cap_drop:
      - SETUID
`)
	s := helperSidecarWithCaps("CHOWN")
	var buf bytes.Buffer
	if err := writeComposePatch(&buf, s, in, "compose.yaml", "app"); err != nil {
		t.Fatalf("writeComposePatch: %v", err)
	}
	got := buf.String()
	// One @@ hunk header. Counts must be present.
	if strings.Count(got, "@@ -") != 1 {
		t.Errorf("expected exactly one hunk header, got:\n%s", got)
	}
	header := ""
	for _, ln := range strings.Split(got, "\n") {
		if strings.HasPrefix(ln, "@@") {
			header = ln
			break
		}
	}
	if header == "" || !strings.Contains(header, "+") {
		t.Errorf("malformed hunk header: %q", header)
	}
}

func TestComposePatch_PreservesLineCountForUnrelatedKeys(t *testing.T) {
	// A common reviewer concern: that the diff drops middle-of-service
	// lines as collateral damage. Spot-check that a service with five
	// other body keys yields a diff that still references all five via
	// context-line presence (' ' prefix).
	in := []byte(`services:
  app:
    image: postgres:16
    container_name: app
    restart: unless-stopped
    environment:
      FOO: bar
    volumes:
      - /data:/data
    cap_drop:
      - SETUID
`)
	s := helperSidecarWithCaps("CHOWN")
	var buf bytes.Buffer
	if err := writeComposePatch(&buf, s, in, "compose.yaml", "app"); err != nil {
		t.Fatalf("writeComposePatch: %v", err)
	}
	got := buf.String()
	// At least the cap_drop line must be removed; the unrelated keys
	// must not appear with leading '-'. We don't require they appear as
	// context (the hunk window is bounded), but they must not be
	// removed.
	for _, key := range []string{"container_name:", "restart:", "FOO: bar", "/data:/data"} {
		if strings.Contains(got, "-    "+key) || strings.Contains(got, "-      "+key) {
			t.Errorf("diff removed unrelated key %q:\n%s", key, got)
		}
	}
}

func TestRun_ComposePatchEndToEnd(t *testing.T) {
	dir := t.TempDir()
	composePath := dir + "/compose.yaml"
	if err := writeFile(composePath, `services:
  postgres-1:
    image: postgres:16
    cap_drop:
      - ALL
`); err != nil {
		t.Fatalf("seed compose: %v", err)
	}
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "compose-patch",
		"--compose-in", composePath,
		"--service", "postgres-1",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	got := out.String()
	if !strings.HasPrefix(got, "--- a/"+composePath+"\n") {
		t.Errorf("diff missing expected --- header:\n%s", got)
	}
	if !strings.Contains(got, "+    cap_add:") {
		t.Errorf("expected cap_add insertion in real-fixture diff:\n%s", got)
	}
}

func TestRun_ComposePatchMissingFlagsFailsEXUsage(t *testing.T) {
	cases := [][]string{
		// no --compose-in
		{"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
			"--container", "postgres-1", "--format", "compose-patch", "--service", "postgres-1"},
		// no --service
		{"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
			"--container", "postgres-1", "--format", "compose-patch", "--compose-in", "/tmp/nope.yaml"},
	}
	for i, args := range cases {
		var out, errBuf bytes.Buffer
		err := run(args, &out, &errBuf)
		if err == nil {
			t.Errorf("case %d: expected error", i)
			continue
		}
		if exitCodeFor(err) != ExitUsage {
			t.Errorf("case %d: exit code = %d, want %d", i, exitCodeFor(err), ExitUsage)
		}
	}
}

func TestRun_ComposePatchFlagsRejectedWithOtherFormats(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "compose",
		"--compose-in", "/tmp/x.yaml",
	}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected --compose-in rejected with --format compose")
	}
	if exitCodeFor(err) != ExitUsage {
		t.Errorf("exit code = %d, want %d", exitCodeFor(err), ExitUsage)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
