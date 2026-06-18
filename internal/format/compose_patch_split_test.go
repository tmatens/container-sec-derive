package format

import (
	"strings"
	"testing"
)

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
