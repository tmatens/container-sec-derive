package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
)

// writeComposePatch emits a unified diff that updates services.<service>'s
// cap_drop and cap_add to match s.CapNames(). The input is the raw bytes of
// a user-supplied compose file; output is patch(1)-applicable.
//
// Parser scope (PLAN.md "no runtime deps beyond Go stdlib without
// discussion" — yaml.v3 deliberately not imported): we only locate the
// named service and its cap_drop / cap_add child blocks. Comments and
// flow-style sequences elsewhere in the file pass through untouched
// because we only diff lines we actively edit.
//
// Output shape: cap_drop is rewritten to [ALL]; cap_add is rewritten to
// the observed set (omitted entirely when empty, matching writeCompose).
// Existing cap_drop / cap_add blocks are replaced in place so the diff is
// minimal and reviewers see no spurious reordering. When both keys are
// missing, the new pair is inserted at the top of the service body. When
// only one is missing, it lands adjacent to the existing partner so the
// two stay together for readability.
func writeComposePatch(w io.Writer, s *Sidecar, original []byte, inPath, service string) error {
	if service == "" {
		return fmt.Errorf("--service is required")
	}
	origLines := splitComposeLines(original)
	loc, err := locateComposeService(origLines, service)
	if err != nil {
		return err
	}

	bodyIndent := strings.Repeat(" ", loc.bodyIndent)
	childIndent := bodyIndent + "  "
	caps := s.CapNames()
	newDrop := []string{
		bodyIndent + "cap_drop:",
		childIndent + "- ALL",
	}
	var newAdd []string
	if len(caps) > 0 {
		newAdd = append(newAdd, bodyIndent+"cap_add:")
		for _, c := range caps {
			newAdd = append(newAdd, childIndent+"- "+c)
		}
	}
	combined := append(append([]string{}, newDrop...), newAdd...)

	dropStart, dropEnd := findChildKeyBlock(origLines, loc, "cap_drop")
	addStart, addEnd := findChildKeyBlock(origLines, loc, "cap_add")
	dropExists := dropStart >= 0
	addExists := addStart >= 0

	var rewrites []capRewrite
	switch {
	case dropExists && addExists:
		rewrites = append(rewrites, capRewrite{dropStart, dropEnd, newDrop})
		rewrites = append(rewrites, capRewrite{addStart, addEnd, newAdd}) // newAdd may be empty → pure removal
	case dropExists && !addExists:
		rewrites = append(rewrites, capRewrite{dropStart, dropEnd, combined})
	case !dropExists && addExists:
		rewrites = append(rewrites, capRewrite{addStart, addEnd, combined})
	default:
		rewrites = append(rewrites, capRewrite{loc.bodyStart, loc.bodyStart, combined})
	}
	sort.Slice(rewrites, func(i, j int) bool { return rewrites[i].start < rewrites[j].start })

	// Apply rewrites to produce the edited line set; bail early if it's
	// byte-identical to the original (caps already match the file).
	edited := applyRewriteSequence(origLines, rewrites)
	if equalLines(origLines, edited) {
		return nil
	}

	// Build the marked stream for the unified diff in a single walk so
	// the output is order-stable and we don't have to LCS-diff after.
	marks := markRewrites(origLines, rewrites)
	return emitUnifiedDiff(w, inPath, marks)
}

// capRewrite is one localized edit: replace origLines[start:end] with
// lines. start==end means a pure insert at start.
type capRewrite struct {
	start, end int
	lines      []string
}

func applyRewriteSequence(orig []string, rewrites []capRewrite) []string {
	out := []string{}
	i, ri := 0, 0
	for i < len(orig) {
		if ri < len(rewrites) && i == rewrites[ri].start {
			out = append(out, rewrites[ri].lines...)
			i = rewrites[ri].end
			ri++
			continue
		}
		out = append(out, orig[i])
		i++
	}
	for ; ri < len(rewrites); ri++ {
		out = append(out, rewrites[ri].lines...)
	}
	return out
}

func markRewrites(orig []string, rewrites []capRewrite) []diffLine {
	var marks []diffLine
	i, ri := 0, 0
	for i < len(orig) {
		if ri < len(rewrites) && i == rewrites[ri].start {
			for j := rewrites[ri].start; j < rewrites[ri].end; j++ {
				marks = append(marks, diffLine{orig[j], '-'})
			}
			for _, ln := range rewrites[ri].lines {
				marks = append(marks, diffLine{ln, '+'})
			}
			i = rewrites[ri].end
			ri++
			continue
		}
		marks = append(marks, diffLine{orig[i], ' '})
		i++
	}
	for ; ri < len(rewrites); ri++ {
		for _, ln := range rewrites[ri].lines {
			marks = append(marks, diffLine{ln, '+'})
		}
	}
	return marks
}

func equalLines(a, b []string) bool {
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

// composeServiceLoc locates a service body within a compose file.
//   nameLine    — index of the "<service>:" line
//   bodyStart   — index of the first body line (== nameLine+1 typically)
//   bodyEnd     — index one past the last body line (the next sibling key
//                 or EOF)
//   bodyIndent  — column count of body-line indentation
type composeServiceLoc struct {
	nameLine   int
	bodyStart  int
	bodyEnd    int
	bodyIndent int
}

func locateComposeService(lines []string, service string) (composeServiceLoc, error) {
	servicesAt := -1
	for i, ln := range lines {
		if leadingSpaces(ln) == 0 && trimmedKey(ln) == "services" {
			servicesAt = i
			break
		}
	}
	if servicesAt < 0 {
		return composeServiceLoc{}, fmt.Errorf("services: block not found in compose file")
	}

	nameAt := -1
	indent := -1
	for i := servicesAt + 1; i < len(lines); i++ {
		ln := lines[i]
		if isBlankOrComment(ln) {
			continue
		}
		col := leadingSpaces(ln)
		if col == 0 {
			break
		}
		if indent == -1 {
			indent = col
		}
		if col == indent && trimmedKey(ln) == service {
			nameAt = i
			break
		}
	}
	if nameAt < 0 {
		return composeServiceLoc{}, fmt.Errorf("service %q not found under services:", service)
	}

	nameIndent := leadingSpaces(lines[nameAt])
	bodyIndent := nameIndent + 2
	bodyStart := nameAt + 1
	for i := nameAt + 1; i < len(lines); i++ {
		ln := lines[i]
		if isBlankOrComment(ln) {
			continue
		}
		col := leadingSpaces(ln)
		if col <= nameIndent {
			break
		}
		bodyIndent = col
		bodyStart = i
		break
	}

	bodyEnd := len(lines)
	for i := bodyStart; i < len(lines); i++ {
		ln := lines[i]
		if isBlankOrComment(ln) {
			continue
		}
		col := leadingSpaces(ln)
		if col <= nameIndent {
			bodyEnd = i
			break
		}
	}

	return composeServiceLoc{
		nameLine:   nameAt,
		bodyStart:  bodyStart,
		bodyEnd:    bodyEnd,
		bodyIndent: bodyIndent,
	}, nil
}

// findChildKeyBlock returns [start, end) line indices for the named child
// key inside loc's service body. Returns (-1, -1) when the key is absent.
// Flow-style values (cap_drop: [X, Y]) collapse to a single-line block.
func findChildKeyBlock(lines []string, loc composeServiceLoc, key string) (int, int) {
	start := -1
	for i := loc.bodyStart; i < loc.bodyEnd; i++ {
		ln := lines[i]
		if isBlankOrComment(ln) {
			continue
		}
		if leadingSpaces(ln) == loc.bodyIndent && trimmedKey(ln) == key {
			start = i
			break
		}
	}
	if start < 0 {
		return -1, -1
	}
	end := start + 1
	for i := start + 1; i < loc.bodyEnd; i++ {
		ln := lines[i]
		if isBlankOrComment(ln) {
			end = i + 1
			continue
		}
		if leadingSpaces(ln) <= loc.bodyIndent {
			break
		}
		end = i + 1
	}
	for end > start+1 && isBlankOrComment(lines[end-1]) {
		end--
	}
	return start, end
}

// trimmedKey extracts the key name from a "key:" or "key: value" line.
// Returns "" for lines that don't look like map keys.
func trimmedKey(line string) string {
	s := strings.TrimLeft(line, " \t")
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "- ") || s == "-" {
		return ""
	}
	if i := strings.Index(s, "#"); i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
		s = strings.TrimRight(s[:i], " \t")
	}
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return ""
	}
	key := strings.TrimSpace(s[:colon])
	if strings.ContainsAny(key, " \t\"'") {
		return ""
	}
	return key
}

func leadingSpaces(line string) int {
	n := 0
	for _, r := range line {
		if r == ' ' {
			n++
			continue
		}
		break
	}
	return n
}

func isBlankOrComment(line string) bool {
	s := strings.TrimSpace(line)
	return s == "" || strings.HasPrefix(s, "#")
}

func splitComposeLines(b []byte) []string {
	var out []string
	scan := bufio.NewScanner(bytes.NewReader(b))
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	for scan.Scan() {
		out = append(out, scan.Text())
	}
	return out
}

// diffLine is one line in the marked-up stream consumed by emitUnifiedDiff.
// kind is ' ' (context), '-' (removal), or '+' (addition).
type diffLine struct {
	text string
	kind byte
}

// emitUnifiedDiff writes a single-hunk unified diff covering all marked
// changes. We collapse to one hunk because cap_drop / cap_add edits are
// always within a small window (the service body); a multi-hunk emitter
// would be premature given the actual edit shape.
func emitUnifiedDiff(w io.Writer, inPath string, marks []diffLine) error {
	first, last := -1, -1
	for i, m := range marks {
		if m.kind != ' ' {
			if first == -1 {
				first = i
			}
			last = i
		}
	}
	if first == -1 {
		return nil
	}
	const ctx = 3
	hunkStart := first - ctx
	if hunkStart < 0 {
		hunkStart = 0
	}
	hunkEnd := last + ctx + 1
	if hunkEnd > len(marks) {
		hunkEnd = len(marks)
	}

	origStart, newStart := 1, 1
	for i := 0; i < hunkStart; i++ {
		switch marks[i].kind {
		case ' ':
			origStart++
			newStart++
		case '-':
			origStart++
		case '+':
			newStart++
		}
	}
	var origCount, newCount int
	for i := hunkStart; i < hunkEnd; i++ {
		switch marks[i].kind {
		case ' ':
			origCount++
			newCount++
		case '-':
			origCount++
		case '+':
			newCount++
		}
	}

	if _, err := fmt.Fprintf(w, "--- a/%s\n", inPath); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "+++ b/%s\n", inPath); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "@@ -%d,%d +%d,%d @@\n", origStart, origCount, newStart, newCount); err != nil {
		return err
	}
	for i := hunkStart; i < hunkEnd; i++ {
		if _, err := fmt.Fprintf(w, "%c%s\n", marks[i].kind, marks[i].text); err != nil {
			return err
		}
	}
	return nil
}
