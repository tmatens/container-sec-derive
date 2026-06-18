package format

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// WriteComposePatch emits a unified diff that updates services.<service>'s
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
// the observed set (omitted entirely when empty, matching WriteCompose).
// Existing cap_drop / cap_add blocks are replaced in place so the diff is
// minimal and reviewers see no spurious reordering. When both keys are
// missing, the new pair is inserted at the top of the service body. When
// only one is missing, it lands adjacent to the existing partner so the
// two stay together for readability.
func WriteComposePatch(w io.Writer, s *sidecar.Sidecar, original []byte, inPath, service string) error {
	if service == "" {
		return fmt.Errorf("--service is required")
	}
	origLines, eol, finalNL := splitComposeLines(original)
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

	if err := refuseAnchoredRewrites(origLines, rewrites); err != nil {
		return err
	}

	// Apply rewrites to produce the edited line set; bail early if it's
	// byte-identical to the original (caps already match the file).
	edited := applyRewriteSequence(origLines, rewrites)
	if equalLines(origLines, edited) {
		return nil
	}

	// Build the marked stream for the unified diff in a single walk so
	// the output is order-stable and we don't have to LCS-diff after.
	marks := markRewrites(origLines, rewrites)
	return emitUnifiedDiff(w, inPath, marks, eol, finalNL)
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
//
//	nameLine    — index of the "<service>:" line
//	bodyStart   — index of the first body line (== nameLine+1 typically)
//	bodyEnd     — index one past the last body line (the next sibling key
//	              or EOF)
//	bodyIndent  — column count of body-line indentation
type composeServiceLoc struct {
	nameLine   int
	bodyStart  int
	bodyEnd    int
	bodyIndent int
}

func locateComposeService(lines []string, service string) (composeServiceLoc, error) {
	// Reject tab indentation before locating anything. YAML forbids tabs for
	// indentation, and leadingSpaces() counts only spaces — so a tab-indented
	// child key reads as column 0 (a top-level key), the locator misses the
	// existing cap_drop/cap_add block, and the patch inserts a duplicate while
	// the stale block survives, defeating "drop ALL" (deep-review M2). Refuse
	// rather than emit a duplicate-key, insecure patch.
	if i := firstTabIndentedLine(lines); i >= 0 {
		return composeServiceLoc{}, fmt.Errorf(
			"compose file uses tab indentation on line %d; YAML forbids tabs for indentation — re-indent with spaces before patching", i+1)
	}

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

// firstTabIndentedLine returns the index of the first non-blank line whose
// leading whitespace contains a tab, or -1 if none. A tab in node-content or a
// value (after the indentation) is fine; only tabs used for indentation are the
// hazard (deep-review M2).
func firstTabIndentedLine(lines []string) int {
	for i, ln := range lines {
		// A tab at the start of the line, or after only spaces, is indentation.
		if rest := strings.TrimLeft(ln, " "); strings.HasPrefix(rest, "\t") && strings.TrimSpace(rest) != "" {
			return i
		}
	}
	return -1
}

// refuseAnchoredRewrites errors if any block this patch would REPLACE (a rewrite
// with start<end) carries a YAML anchor, alias, or merge key. Rewriting such a
// block would drop an anchor definition that aliases elsewhere depend on, or
// silently expand an alias — neither is a safe in-place edit, so the patch
// formatters refuse rather than emit a corrupting diff (deep-review L7). Pure
// insertions (start==end) touch no existing lines and are always safe; blocks
// elsewhere in the file (including other keys of the same service) are not
// examined, so an unrelated `logging: *shared` does not block a cap patch.
func refuseAnchoredRewrites(lines []string, rewrites []capRewrite) error {
	for _, rw := range rewrites {
		for i := rw.start; i < rw.end && i < len(lines); i++ {
			if tok := yamlAnchorToken(lines[i]); tok != "" {
				return fmt.Errorf(
					"refusing to rewrite an anchored block: line %d uses a YAML %s; resolve the anchor/alias or edit the block by hand", i+1, tok)
			}
		}
	}
	return nil
}

// yamlAnchorToken reports the kind of YAML node property a line carries in
// value or sequence-item position ("anchor", "alias", or "merge key"), or "" for
// none. It inspects only value position, so a scalar that merely contains '&' or
// '*' (e.g. a password) is not mistaken for an anchor.
func yamlAnchorToken(line string) string {
	s := strings.TrimLeft(line, " \t")
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	if strings.HasPrefix(s, "<<:") { // merge key: `<<: *base`
		return "merge key"
	}
	if strings.HasPrefix(s, "- ") || s == "-" { // sequence item: `- &x` / `- *x`
		v := strings.TrimSpace(strings.TrimPrefix(s, "-"))
		switch {
		case strings.HasPrefix(v, "&"):
			return "anchor"
		case strings.HasPrefix(v, "*"):
			return "alias"
		}
		return ""
	}
	if colon := strings.IndexByte(s, ':'); colon >= 0 { // mapping value: `k: &x` / `k: *x`
		v := strings.TrimSpace(s[colon+1:])
		switch {
		case strings.HasPrefix(v, "&"):
			return "anchor"
		case strings.HasPrefix(v, "*"):
			return "alias"
		}
	}
	return ""
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

// splitComposeLines splits a compose file into lines and reports the file's
// line-ending convention and whether it ends with a newline. It splits on "\n"
// directly rather than via bufio.Scanner so that (a) a line longer than 1MB is
// not silently truncated with the rest of the file dropped (deep-review L8), and
// (b) CRLF files keep their "\r\n" terminator on re-emit instead of being
// flattened to LF (deep-review L6). Returned lines are stripped of any trailing
// "\r" so the locator sees clean content; emitUnifiedDiff re-adds eol. The
// finalNewline flag lets emitUnifiedDiff emit a "\ No newline at end of file"
// marker when the original lacks a trailing newline (deep-review L5).
func splitComposeLines(b []byte) (lines []string, eol string, finalNewline bool) {
	if len(b) == 0 {
		return nil, "\n", false
	}
	s := string(b)
	finalNewline = strings.HasSuffix(s, "\n")
	eol = "\n"
	if strings.Contains(s, "\r\n") {
		eol = "\r\n"
	}
	lines = strings.Split(s, "\n")
	// A trailing "\n" leaves an empty final element from Split; drop it so the
	// line set reflects actual lines, not a phantom blank.
	if finalNewline && len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines, eol, finalNewline
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
func emitUnifiedDiff(w io.Writer, inPath string, marks []diffLine, eol string, finalNewline bool) error {
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

	// The original file's final line (last mark present in the OLD file, i.e.
	// not an addition) and the new file's final line (last mark not a removal).
	// When the original lacks a trailing newline, whichever of these falls in
	// the hunk is followed by the "\ No newline at end of file" marker so the
	// diff applies cleanly (deep-review L5).
	oldFinal, newFinal := -1, -1
	for i := range marks {
		if marks[i].kind != '+' {
			oldFinal = i
		}
		if marks[i].kind != '-' {
			newFinal = i
		}
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
		m := marks[i]
		// A line with no trailing newline keeps the diff's own "\n" separator and
		// is followed by the marker; every other line uses the file's eol ("\n"
		// or "\r\n") so CRLF round-trips byte-for-byte.
		noNewline := !finalNewline &&
			((i == oldFinal && m.kind != '+') || (i == newFinal && m.kind != '-'))
		if noNewline {
			if _, err := fmt.Fprintf(w, "%c%s\n\\ No newline at end of file\n", m.kind, m.text); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "%c%s%s", m.kind, m.text, eol); err != nil {
			return err
		}
	}
	return nil
}
