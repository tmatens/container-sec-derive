package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// helperSidecarWithCaps returns a Sidecar carrying caps in the order
// supplied; matches what aggregate() produces for downstream formatters.
func helperSidecarWithCaps(caps ...string) *sidecar.Sidecar {
	s := sidecar.NewSidecar()
	for _, c := range caps {
		s.Capabilities = append(s.Capabilities, sidecar.Capability{Name: c})
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
		if exit.CodeFor(err) != exit.Usage {
			t.Errorf("case %d: exit code = %d, want %d", i, exit.CodeFor(err), exit.Usage)
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
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("exit code = %d, want %d", exit.CodeFor(err), exit.Usage)
	}
}

// TestComposePatch_RejectsTabIndentation is the M2 regression: a tab-indented
// compose file would make leadingSpaces() read the cap blocks as column 0, the
// locator miss them, and the patch insert duplicate keys while the stale block
// survives (defeating "drop ALL"). The patch must refuse such input outright.
func TestComposePatch_RejectsTabIndentation(t *testing.T) {
	// Tab-indented service + cap_add (YAML-invalid, but the shape that used to
	// produce a duplicate-key patch).
	in := []byte("services:\n\tapp:\n\t\timage: postgres:16\n\t\tcap_add:\n\t\t\t- CHOWN\n")
	s := helperSidecarWithCaps("SETGID")
	var buf bytes.Buffer
	err := writeComposePatch(&buf, s, in, "compose.yaml", "app")
	if err == nil {
		t.Fatalf("expected refusal for tab-indented file; got patch:\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "tab indentation") {
		t.Errorf("error = %v, want a tab-indentation refusal", err)
	}
	if buf.Len() != 0 {
		t.Errorf("no patch should be emitted for a rejected file, got:\n%s", buf.String())
	}

	// A space-indented file containing only a tab inside a value is fine.
	ok := []byte("services:\n  app:\n    image: postgres:16\n    environment:\n      MSG: \"a\tb\"\n    cap_add:\n      - CHOWN\n")
	buf.Reset()
	if err := writeComposePatch(&buf, s, ok, "compose.yaml", "app"); err != nil {
		t.Errorf("space-indented file with a tab in a value should patch fine: %v", err)
	}
}

// TestComposePatch_RefusesAnchoredBlock is the L7 regression: rewriting a block
// that defines a YAML anchor (or is an alias) would drop the anchor / silently
// expand the alias and break references elsewhere. The patch must refuse — but
// only for the block it would rewrite, not for unrelated anchors in the service.
func TestComposePatch_RefusesAnchoredBlock(t *testing.T) {
	s := helperSidecarWithCaps("SETGID")

	// cap_add value is an anchor definition -> refuse.
	anchored := []byte("services:\n  app:\n    image: postgres:16\n    cap_add: &appcaps\n      - CHOWN\n")
	var buf bytes.Buffer
	err := writeComposePatch(&buf, s, anchored, "compose.yaml", "app")
	if err == nil {
		t.Fatalf("expected refusal for anchored cap_add; got patch:\n%s", buf.String())
	}
	if !strings.Contains(err.Error(), "anchor") {
		t.Errorf("error = %v, want an anchor refusal", err)
	}

	// cap_add is an alias -> refuse.
	aliased := []byte("services:\n  app:\n    image: postgres:16\n    cap_add: *appcaps\n")
	buf.Reset()
	if err := writeComposePatch(&buf, s, aliased, "compose.yaml", "app"); err == nil {
		t.Fatalf("expected refusal for aliased cap_add; got:\n%s", buf.String())
	}

	// An anchor in an UNRELATED block of the same service must NOT block the
	// cap patch — precision matters (no over-rejection).
	unrelated := []byte("services:\n  app:\n    image: postgres:16\n    logging: &log\n      driver: json-file\n    cap_add:\n      - CHOWN\n")
	buf.Reset()
	if err := writeComposePatch(&buf, s, unrelated, "compose.yaml", "app"); err != nil {
		t.Errorf("anchor in an unrelated block must not block the cap patch: %v", err)
	}
	if !strings.Contains(buf.String(), "+      - SETGID") {
		t.Errorf("expected a cap_add rewrite despite the unrelated anchor:\n%s", buf.String())
	}
}

// TestSplitComposeLines covers the line-reader invariants behind L6/L8: CRLF
// detection with "\r" stripped from stored lines, trailing-newline tracking, and
// no truncation of a >1MB line (which bufio.Scanner's 1MB cap used to drop along
// with the rest of the file).
func TestSplitComposeLines(t *testing.T) {
	// LF, trailing newline.
	lines, eol, fin := splitComposeLines([]byte("a\nb\n"))
	if eol != "\n" || !fin || len(lines) != 2 || lines[0] != "a" || lines[1] != "b" {
		t.Errorf("LF: lines=%q eol=%q fin=%v", lines, eol, fin)
	}
	// No trailing newline.
	lines, _, fin = splitComposeLines([]byte("a\nb"))
	if fin || len(lines) != 2 || lines[1] != "b" {
		t.Errorf("no-final-newline: lines=%q fin=%v", lines, fin)
	}
	// CRLF: "\r" stripped from content, eol records the convention.
	lines, eol, fin = splitComposeLines([]byte("a\r\nb\r\n"))
	if eol != "\r\n" || !fin || lines[0] != "a" || lines[1] != "b" {
		t.Errorf("CRLF: lines=%q eol=%q fin=%v", lines, eol, fin)
	}
	// A >1MB line must not be dropped, and lines after it must survive.
	huge := strings.Repeat("x", 1<<21) // 2MB, well past the old 1MB scanner cap
	lines, _, _ = splitComposeLines([]byte("# " + huge + "\nservices:\n  app:\n"))
	if len(lines) != 3 || lines[1] != "services:" || lines[2] != "  app:" {
		t.Errorf(">1MB line truncated the file: got %d lines, last=%q", len(lines), lines[len(lines)-1])
	}
}

// TestComposePatch_PreservesCRLF is the L6 regression: a CRLF compose file must
// round-trip — context and added diff lines keep "\r\n" so the patch applies to
// the original bytes instead of flipping the file to LF.
func TestComposePatch_PreservesCRLF(t *testing.T) {
	in := []byte("services:\r\n  app:\r\n    image: x\r\n    cap_add:\r\n      - CHOWN\r\n")
	s := helperSidecarWithCaps("SETGID")
	var buf bytes.Buffer
	if err := writeComposePatch(&buf, s, in, "compose.yaml", "app"); err != nil {
		t.Fatalf("writeComposePatch: %v", err)
	}
	out := buf.String()
	// Added cap_add lines carry CRLF.
	if !strings.Contains(out, "+    cap_add:\r\n") || !strings.Contains(out, "+      - SETGID\r\n") {
		t.Errorf("added lines lost CRLF:\n%q", out)
	}
	// A context line carries CRLF too (so it matches the original bytes).
	if !strings.Contains(out, " services:\r\n") {
		t.Errorf("context line lost CRLF:\n%q", out)
	}
}

// TestComposePatch_NoTrailingNewline is the L5 regression: when the original
// lacks a final newline, the diff must carry the "\ No newline at end of file"
// marker so git apply / patch don't choke.
func TestComposePatch_NoTrailingNewline(t *testing.T) {
	// cap_add block is the file's tail and the file has no trailing newline.
	in := []byte("services:\n  app:\n    image: x\n    cap_add:\n      - CHOWN")
	s := helperSidecarWithCaps("SETGID")
	var buf bytes.Buffer
	if err := writeComposePatch(&buf, s, in, "compose.yaml", "app"); err != nil {
		t.Fatalf("writeComposePatch: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "\\ No newline at end of file") {
		t.Errorf("missing no-newline marker for a file without a trailing newline:\n%s", out)
	}
	// The removed old final line precedes a marker.
	if !strings.Contains(out, "-      - CHOWN\n\\ No newline at end of file") {
		t.Errorf("marker not attached to the removed final line:\n%s", out)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
