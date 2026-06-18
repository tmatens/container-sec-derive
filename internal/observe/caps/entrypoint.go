package caps

// Entrypoint cross-check (PLAN.md §Workload coverage item 1): derive an
// "expected" cap set from static image metadata so the tool can flag the
// "workload didn't exercise initdb" class of gap. The cross-check is a
// proxy signal, not a coverage measurement; false positives are expected
// and the heuristic table is deliberately narrow (see PLAN.md table).
//
// v0.1.0-rc phase A: signals come from `docker inspect` (entrypoint/cmd
// argv) and `docker history --no-trunc` (setcap in Dockerfile layers).
// Reading script contents out of image layers is deferred; most scripted
// entrypoints (e.g. postgres's docker-entrypoint.sh) will therefore produce
// an empty expected set and a vacuously-clean cross-check under argv-only.
// That's acceptable informational data for the phase B decision: either
// the signal is useful enough to expand (add script reading) or thin
// enough to drop.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// crossCheckStatusOK is the sentinel crossCheckStatus value used by
// ApplyEntrypointCrossCheck when the inspection (live or fixture)
// succeeded -- regardless of whether any signals actually fired.
// Anything else non-empty is a short human-readable reason the check
// could not run and gets surfaced as an "unavailable" factor.
const crossCheckStatusOK = "ok"

// entrypointInspection is the static image metadata that feeds the
// cross-check. Populated by inspectEntrypoint (live docker) or by
// loadInspectionFixture (tests). Image is informational and used in
// error prose; it is not part of the heuristic input.
//
// RepoDigests carries `docker inspect`'s top-level RepoDigests array
// (one "<repo>@sha256:..." entry per published push). Step 17 promotes
// the matching digest onto Sidecar.ImageDigest so the compose-lint
// contribution gate can pin profiles to a digest. Locally-built images
// that were never pushed have an empty RepoDigests; the contract gate
// then refuses cleanly with an "image_digest missing" violation.
type entrypointInspection struct {
	Image        string   `json:"image"`
	Entrypoint   []string `json:"entrypoint"`
	Cmd          []string `json:"cmd"`
	HistoryLines []string `json:"history_lines"`
	RepoDigests  []string `json:"repo_digests,omitempty"`
}

// argvHeuristic is one row of PLAN.md §Workload coverage item 1's table.
// Adding or widening rows past what PLAN.md specifies is a design change,
// not a tuning change -- the false-positive rate of each row is load-bearing.
type argvHeuristic struct {
	signal string   // matched as a word, case-insensitive
	caps   []string // caps expected when signal is present
	prose  string   // short phrase naming the signal for warning messages
}

// argvHeuristics is the PLAN.md table, with the `chown`/`chmod` row
// expanded into two entries so each signal produces its own attributed
// warning. Dedupe happens at the final warning-text layer.
var argvHeuristics = []argvHeuristic{
	{"chown", []string{"CHOWN", "FOWNER", "DAC_OVERRIDE"}, "entrypoint references `chown`"},
	{"chmod", []string{"CHOWN", "FOWNER", "DAC_OVERRIDE"}, "entrypoint references `chmod`"},
	{"gosu", []string{"SETUID", "SETGID"}, "entrypoint references `gosu`"},
	{"su-exec", []string{"SETUID", "SETGID"}, "entrypoint references `su-exec`"},
	{"setpriv", []string{"SETUID", "SETGID"}, "entrypoint references `setpriv`"},
	{"mount", []string{"SYS_ADMIN"}, "entrypoint references `mount`"},
	{"umount", []string{"SYS_ADMIN"}, "entrypoint references `umount`"},
	{"ping", []string{"NET_RAW"}, "entrypoint references `ping`"},
}

// setcapWordRE gates history-line scanning: only lines containing the
// literal word `setcap` are mined for cap names. This keeps a layer like
// `RUN apt-get install libcap2-bin` (which mentions capabilities but
// doesn't set any) from contributing signals.
var setcapWordRE = regexp.MustCompile(`(?i)\bsetcap\b`)

// capTokenRE extracts `cap_xxx` tokens from setcap lines. Matches the
// trailing name only; the `cap_` prefix is stripped in output so the
// result lines up with NormalizeCap's post-CAP_-strip form.
var capTokenRE = regexp.MustCompile(`(?i)\bcap_([a-z0-9_]+)`)

// signalHit records one triggered heuristic so computeCoverageWarnings
// can attribute a missing cap back to the signal that expected it.
// Order of hits mirrors argvHeuristics + history order so warnings are
// stable across runs without a separate sort pass.
type signalHit struct {
	prose         string
	triggeredCaps []string
}

// inspectEntrypoint runs `docker inspect` + `docker history` for image
// and returns the combined metadata. Both subprocesses must succeed; a
// partial-data path would force callers to distinguish "no history" from
// "history unavailable," which is more cognitive load than it's worth
// for a proxy signal. Runtime is hardcoded to `docker` in v0.1.0-rc --
// runtime abstraction (containerd/podman) lands once, across observe and
// inspect, in a later step.
func inspectEntrypoint(ctx context.Context, image string) (entrypointInspection, error) {
	insp := entrypointInspection{Image: image}
	if image == "" {
		return insp, fmt.Errorf("no image reference available for cross-check")
	}

	// Combine the two fields we need into one inspect call. RepoDigests is
	// top-level on the inspect object, not under .Config -- step 17 added
	// it for digest enrichment. Two separate `docker inspect` invocations
	// would also work but cost an extra subprocess per run.
	const inspectFormat = `{"config":{{json .Config}},"repo_digests":{{json .RepoDigests}}}`
	// "--" terminates flag parsing so an image ref beginning with "-" can't be
	// smuggled in as a docker flag (deep-review L2; defense-in-depth, not injection).
	inspectOut, err := exec.CommandContext(ctx, "docker", "inspect", "--format", inspectFormat, "--", image).Output()
	if err != nil {
		return insp, fmt.Errorf("docker inspect %s: %w", image, err)
	}
	var combined struct {
		Config struct {
			Entrypoint []string `json:"Entrypoint"`
			Cmd        []string `json:"Cmd"`
		} `json:"config"`
		RepoDigests []string `json:"repo_digests"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(inspectOut), &combined); err != nil {
		return insp, fmt.Errorf("parse docker inspect output: %w", err)
	}
	insp.Entrypoint = combined.Config.Entrypoint
	insp.Cmd = combined.Config.Cmd
	insp.RepoDigests = combined.RepoDigests

	historyOut, err := exec.CommandContext(ctx, "docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", "--", image).Output()
	if err != nil {
		return insp, fmt.Errorf("docker history %s: %w", image, err)
	}
	scan := bufio.NewScanner(bytes.NewReader(historyOut))
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line != "" {
			insp.HistoryLines = append(insp.HistoryLines, line)
		}
	}
	return insp, nil
}

// loadInspectionFixture reads a pre-captured entrypointInspection from
// path. Used by --inspect-fixture in tests and hermetic CI runs so the
// cross-check is exercisable without a docker daemon.
func loadInspectionFixture(path string) (entrypointInspection, error) {
	var insp entrypointInspection
	b, err := os.ReadFile(path)
	if err != nil {
		return insp, fmt.Errorf("read inspect fixture %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &insp); err != nil {
		return insp, fmt.Errorf("parse inspect fixture %s: %w", path, err)
	}
	return insp, nil
}

// deriveExpectedCaps applies PLAN.md §Workload coverage item 1 to insp.
// Returns the sorted union cap set and the ordered list of signals that
// produced it; callers pass the hits into computeCoverageWarnings so
// each missing cap can be attributed to a specific heuristic.
func deriveExpectedCaps(insp entrypointInspection) ([]string, []signalHit) {
	argv := strings.Join(append(append([]string{}, insp.Entrypoint...), insp.Cmd...), " ")
	var hits []signalHit
	set := map[string]struct{}{}
	for _, h := range argvHeuristics {
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(h.signal) + `\b`)
		if !re.MatchString(argv) {
			continue
		}
		hits = append(hits, signalHit{prose: h.prose, triggeredCaps: h.caps})
		for _, c := range h.caps {
			set[c] = struct{}{}
		}
	}
	for _, cap := range setcapCapsFromHistory(insp.HistoryLines) {
		hits = append(hits, signalHit{
			prose:         fmt.Sprintf("Dockerfile history grants `cap_%s` via `setcap`", strings.ToLower(cap)),
			triggeredCaps: []string{cap},
		})
		set[cap] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out, hits
}

// setcapCapsFromHistory walks history lines and returns every cap name
// mentioned on a line that also contains the literal `setcap`. Cap names
// are returned in the post-CAP_-strip form (CHOWN, not cap_chown).
func setcapCapsFromHistory(lines []string) []string {
	seen := map[string]struct{}{}
	for _, line := range lines {
		if !setcapWordRE.MatchString(line) {
			continue
		}
		for _, m := range capTokenRE.FindAllStringSubmatch(line, -1) {
			seen[strings.ToUpper(m[1])] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ApplyEntrypointCrossCheck populates s.ExpectedCapsFromEntrypoint,
// s.CoverageWarnings, and s.crossCheckStatus. Priority order for the
// inspection source:
//
//  1. --inspect-fixture <path> (tests, hermetic CI)
//  2. Live `docker inspect` + `docker history` against s.Image
//  3. Skip (fixture mode without --inspect-fixture, or no image ref)
//
// Phase A (PLAN.md §Workload coverage item 2 deferred): divergence is
// recorded but does NOT force confidence to low; ComputeConfidence reads
// the populated fields and emits an informational factor.
func ApplyEntrypointCrossCheck(s *sidecar.Sidecar, inspectFixture string, fixtureMode bool, stderrSink io.Writer) {
	var (
		insp entrypointInspection
		err  error
	)
	switch {
	case inspectFixture != "":
		insp, err = loadInspectionFixture(inspectFixture)
		if err != nil {
			s.CrossCheckStatus = fmt.Sprintf("inspect fixture unreadable: %v", err)
			return
		}
	case fixtureMode:
		// Hermetic fixture mode; caller did not provide --inspect-fixture.
		// Skip silently so tests that do not care about the cross-check
		// continue producing stable sidecars under no rubric pressure.
		return
	case s.Image == "":
		s.CrossCheckStatus = "no image reference available for cross-check"
		return
	default:
		ctx, cancel := context.WithTimeout(context.Background(), observe.InspectDefaultTimeout)
		defer cancel()
		insp, err = inspectEntrypoint(ctx, s.Image)
		if err != nil {
			if stderrSink != nil {
				fmt.Fprintf(stderrSink, "csd: entrypoint cross-check unavailable: %v\n", err)
			}
			s.CrossCheckStatus = truncateReason(err.Error())
			return
		}
	}

	expected, hits := deriveExpectedCaps(insp)
	s.ExpectedCapsFromEntrypoint = expected
	s.CoverageWarnings = computeCoverageWarnings(hits, s.CapNames())
	// Promote a matching digest onto the sidecar so the compose-lint
	// contribution gate can pin to it. Pre-populated values win -- a
	// caller that already attributed a digest (future --digest flag,
	// fixture override) is authoritative over inspect's view.
	if s.ImageDigest == "" {
		s.ImageDigest = pickRepoDigest(s.Image, insp.RepoDigests)
	}
	s.CrossCheckStatus = sidecar.CrossCheckStatusOK
	if stderrSink != nil {
		for _, w := range s.CoverageWarnings {
			fmt.Fprintf(stderrSink, "csd: coverage_warning: %s\n", w)
		}
	}
}

// pickRepoDigest returns the bare "sha256:..." digest from repoDigests
// whose repo prefix matches imageRef's repo (everything before the tag
// or @-digest). Returns "" when no digest matches; callers leave
// Sidecar.ImageDigest empty in that case rather than guess at a wrong
// repo's digest.
//
// `docker inspect` formats RepoDigests entries as "<repo>@sha256:...".
// We strip the "<repo>@" prefix so the value lines up with the format
// the compose-lint contribution flow expects (`validated_image:
// postgres:16@sha256:...` is built by appending "@" + ImageDigest).
func pickRepoDigest(imageRef string, repoDigests []string) string {
	repo := imageRef
	if at := strings.Index(repo, "@"); at >= 0 {
		repo = repo[:at]
	}
	if col := strings.LastIndex(repo, ":"); col >= 0 {
		repo = repo[:col]
	}
	for _, d := range repoDigests {
		i := strings.Index(d, "@")
		if i < 0 {
			continue
		}
		if d[:i] == repo {
			return d[i+1:]
		}
	}
	return ""
}

// truncateReason keeps an unavailable-factor string short enough that it
// doesn't push the factors list past a reader's attention span while
// preserving the head of the error (command + image name) that actually
// identifies the cause.
func truncateReason(s string) string {
	const limit = 200
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}

// computeCoverageWarnings emits one warning per (signal, missing-cap)
// pair that isn't covered by observed. Warning text follows PLAN.md
// §Workload coverage item 2's shape. Duplicates (same signal triggering
// the same cap twice) are deduped at the text level; distinct signals
// expecting the same cap each get their own line so reviewers can trace
// every warning back to the static evidence that produced it.
func computeCoverageWarnings(hits []signalHit, observed []string) []string {
	obs := map[string]struct{}{}
	for _, c := range observed {
		obs[c] = struct{}{}
	}
	seen := map[string]struct{}{}
	// Initialize non-nil so a zero-warning run serializes as [] not null
	// (PLAN.md §Output schema, enforced by TestNewSidecar_NoNullCollections).
	out := []string{}
	for _, h := range hits {
		for _, cap := range h.triggeredCaps {
			if _, ok := obs[cap]; ok {
				continue
			}
			msg := fmt.Sprintf(
				"%s but %s was not observed. Likely cause: workload did not exercise a code path that needs it.",
				h.prose, cap,
			)
			if _, dup := seen[msg]; dup {
				continue
			}
			seen[msg] = struct{}{}
			out = append(out, msg)
		}
	}
	sort.Strings(out)
	return out
}
