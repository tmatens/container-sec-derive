// Package obstest holds test-only helpers shared across the observer
// packages' test suites (and the root CLI tests). It is imported solely from
// *_test.go files, so it never reaches the csd binary; it exists because Go
// requires a package's white-box tests to live in that package's directory, so
// helpers used by more than one such package need a shared importable home.
package obstest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/ig"
)

// WriteTemp writes content to a uniquely-named temp file and returns its path.
func WriteTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := t.TempDir() + "/" + name
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// EqualSlice reports whether a and b have the same elements in the same order.
func EqualSlice(a, b []string) bool {
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

// FakeIGRun writes a fake `ig` shell script that prints PinnedIGVersion on
// `version` and replays stdoutNDJSON/stderrText on `run`. Returns its path,
// suitable for --ig in a run()/observe test.
func FakeIGRun(t *testing.T, stdoutNDJSON, stderrText string) string {
	t.Helper()
	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.ndjson")
	errFile := filepath.Join(dir, "err.txt")
	if err := os.WriteFile(outFile, []byte(stdoutNDJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errFile, []byte(stderrText), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ig-fake")
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  version) echo " + ig.PinnedIGVersion + "; exit 0;;\n" +
		"  run) cat " + outFile + "; cat " + errFile + " >&2; exit 0;;\n" +
		"esac\n" +
		"exit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// ContainsSubstr reports whether any element of ss contains sub.
func ContainsSubstr(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
