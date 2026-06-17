package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestParseIGStderr_LossLines checks the normal path: every `lost N samples`
// line is summed, non-matching diagnostics are ignored.
func TestParseIGStderr_LossLines(t *testing.T) {
	in := "starting trace_capabilities\n" +
		"lost 4 samples\n" +
		"some other diagnostic\n" +
		"lost 6 samples\n"
	if got := parseIGStderr(strings.NewReader(in), nil); got != 10 {
		t.Errorf("parseIGStderr = %d, want 10", got)
	}
}

// TestParseIGStderr_OversizedLineDoesNotDropSubsequentCounts is the M1
// regression: an oversized line (larger than bufio.Scanner's old 1MB cap) must
// NOT stop parsing — the loss lines after it must still be counted. With the old
// scanner the oversized line stopped Scan() and every subsequent drop count was
// silently lost, under-reporting drops and defeating the drop-rate abort.
func TestParseIGStderr_OversizedLineDoesNotDropSubsequentCounts(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(strings.Repeat("x", 2*1024*1024)) // 2MB single line, no match
	buf.WriteByte('\n')
	buf.WriteString("lost 7 samples\n")
	buf.WriteString("lost 3 samples\n")

	if got := parseIGStderr(&buf, nil); got != 10 {
		t.Errorf("parseIGStderr = %d, want 10 — loss lines after an oversized line must survive (M1)", got)
	}
}

// TestParseIGStderr_NoTrailingNewline ensures a final line without a trailing
// newline (the EOF case) is still parsed.
func TestParseIGStderr_NoTrailingNewline(t *testing.T) {
	if got := parseIGStderr(strings.NewReader("lost 5 samples"), nil); got != 5 {
		t.Errorf("parseIGStderr = %d, want 5 (final line without newline)", got)
	}
}
