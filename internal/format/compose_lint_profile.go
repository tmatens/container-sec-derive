package format

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/ig"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// The compose-lint-profile formatters emit one document per csd run, shaped to
// the compose-lint catalog schema (profile.schema.json, Draft 2020-12). The
// document is an aggregate-per-image: top-level schema_version/image/status and
// a `dimensions:` map. Each csd run observes exactly one dimension, so csd emits
// a single-dimension document; the full profile is the union of caps + fs +
// devices + … under one `image`, unioned downstream by the catalog automation
// (merge decision A -- see README §compose-lint profile contribution). This
// keeps csd's per-run model intact (no `csd merge` subcommand) and matches the
// automation consumer the trust model assumes (ADR-017 §7).
//
// The formatter is also the acceptance-contract enforcer: it refuses to emit
// unless every term of Check*ComposeLintContract is met. When allowExploratory
// is true, a failing sidecar is still emitted with `status: exploratory` and a
// top-level `acceptance_contract_violations:` list, so the receiving catalog's
// exploratory/ path can surface the gaps without pretending the profile is
// validated. validated_via lists only `bpf-observation`; the receiving-side CI
// pipeline appends `ci-smoke` once the profile passes the smoke gate.

// WriteComposeLintProfile emits the CL-0006 capabilities dimension: cap_drop:
// [ALL] + the observed cap_add.
func WriteComposeLintProfile(w io.Writer, s *sidecar.Sidecar, allowExploratory bool) error {
	violations := CheckComposeLintContract(s)
	if len(violations) > 0 && !allowExploratory {
		return composeLintContractError(violations)
	}
	return writeComposeLintAggregate(w, s, "capabilities", "caps", violations,
		func(sw *stickyWriter, ind string) {
			sw.printf("%scap_drop: [ALL]\n", ind)
			sw.printf("%scap_add: [%s]\n", ind, strings.Join(s.CapNames(), ", "))
		})
}

// writeComposeLintAggregate emits the shared catalog document envelope --
// schema_version/image/status, the optional acceptance_contract_violations
// list, and the single `dimensions.<dimKey>:` entry whose body is written by
// writeBody and whose derivation is written by writeComposeLintDerivation.
// All five observer formatters funnel through here so the envelope is
// single-sourced.
func writeComposeLintAggregate(w io.Writer, s *sidecar.Sidecar, dimKey, observer string, violations []string, writeBody func(*stickyWriter, string)) error {
	sw := &stickyWriter{w: w}
	status := "validated"
	if len(violations) > 0 {
		status = "exploratory"
	}
	// schema_version is quoted so "1.0" stays a string, not a YAML float.
	sw.printf("schema_version: \"1.0\"\n")
	sw.printf("image: %s\n", ComposeLintImage(s))
	sw.printf("status: %s\n", status)
	if len(violations) > 0 {
		sw.printf("acceptance_contract_violations:\n")
		for _, v := range violations {
			sw.printf("  - %s\n", v)
		}
	}
	sw.printf("dimensions:\n")
	sw.printf("  %s:\n", dimKey)
	writeBody(sw, "    ")
	writeComposeLintDerivation(sw, s, observer, "    ")
	return sw.err
}

// writeComposeLintDerivation emits a dimension's `derivation:` block in a fixed
// field order matching the catalog schema. validated_date and the version
// strings are quoted so a naive YAML parser doesn't coerce them (a bare date
// parses to a timestamp, a bare "1.5" to a float). workload_sha256 is quoted so
// an all-numeric hash can't be read as an integer.
func writeComposeLintDerivation(sw *stickyWriter, s *sidecar.Sidecar, observer, ind string) {
	d := ind + "  "
	sw.printf("%sderivation:\n", ind)
	sw.printf("%stool: container-sec-derive\n", d)
	sw.printf("%stool_version: %q\n", d, s.ToolVersion)
	sw.printf("%ssidecar_schema_version: %q\n", d, s.SchemaVersion)
	sw.printf("%sobserver: %s\n", d, observer)
	sw.printf("%svalidated_image: %s\n", d, composeLintValidatedImage(s))
	sw.printf("%svalidated_date: %q\n", d, s.ObservedAt.UTC().Format("2006-01-02"))
	sw.printf("%sduration_seconds: %d\n", d, s.DurationSeconds)
	sw.printf("%sconfidence: %s\n", d, s.Confidence.Level)
	sw.printf("%sworkload: %s\n", d, s.Workload)
	sw.printf("%sworkload_sha256: %q\n", d, composeLintWorkloadHash(s))
	sw.printf("%svalidated_via: [bpf-observation]\n", d)
	// observation_backend records how the kernel signal was captured. All
	// current observers use built-in ig gadgets, so gadgets is empty; a
	// csd-authored gadget must thread its image+digest here (schema requires
	// {name,image,digest} per gadget) once the gadget-migration work lands.
	sw.printf("%sobservation_backend:\n", d)
	sw.printf("%s  ig_version: %s\n", d, ig.PinnedIGVersion)
	sw.printf("%s  gadgets: []\n", d)
}

// stickyWriter accumulates the first write error so the aggregate/derivation
// emitters can stay linear instead of threading an error through every Fprintf.
type stickyWriter struct {
	w   io.Writer
	err error
}

func (sw *stickyWriter) printf(format string, a ...any) {
	if sw.err != nil {
		return
	}
	_, sw.err = fmt.Fprintf(sw.w, format, a...)
}

// composeLintContractError is the shared refuse-path error: the contract was
// not met and --allow-exploratory was not passed. The violations are listed in
// the deterministic check order so the diagnostic is stable.
func composeLintContractError(violations []string) error {
	return fmt.Errorf("compose-lint-profile acceptance contract not met; pass --allow-exploratory to emit anyway:\n  - %s",
		strings.Join(violations, "\n  - "))
}

// composeLintWorkloadHash returns the hex sha256 of the workload script, the
// tamper-evident reproducibility anchor the catalog gate re-checks. Empty when
// the workload is unset or unreadable -- an exploratory draft may legitimately
// carry no hash (the missing/unreadable workload is itself a recorded
// violation); a validated document always has a readable workload by contract.
func composeLintWorkloadHash(s *sidecar.Sidecar) string {
	if s.Workload == "" {
		return ""
	}
	data, err := os.ReadFile(s.Workload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ComposeLintMinDurationSeconds is PLAN.md's 5-minute floor for a
// contributable profile. Shorter windows don't carry enough exercise
// coverage to justify a catalog entry.
const ComposeLintMinDurationSeconds = 300

// ComposeLintMaxDropRate mirrors PLAN.md's <1% drop-rate bar for the
// contribution gate. This is strictly below the confidence rubric's
// 1% downgrade threshold -- the same number, but the formatter enforces
// it independently so a rubric change doesn't silently loosen the gate.
const ComposeLintMaxDropRate = 0.01

// CheckComposeLintContract returns the acceptance-contract violations in
// a fixed check order. Empty slice means the sidecar clears the gate.
// Order matters: the output is the user-facing diagnostic and also
// becomes the exploratory-mode annotation, so it must be deterministic.
func CheckComposeLintContract(s *sidecar.Sidecar) []string {
	var v []string
	switch {
	case s.SchemaVersion == "":
		v = append(v, "schema_version missing")
	case !sidecar.SchemaMajorCompatible(s.SchemaVersion):
		v = append(v, fmt.Sprintf("schema_version %q outside current major (%d.x)", s.SchemaVersion, sidecar.CurrentSchemaMajor()))
	}
	if s.ImageDigest == "" {
		v = append(v, "image_digest missing (profile cannot be pinned to a digest)")
	}
	switch {
	case s.Workload == "":
		v = append(v, "workload path not set")
	default:
		if _, err := os.Stat(s.Workload); err != nil {
			v = append(v, fmt.Sprintf("workload file %q not readable: %v", s.Workload, err))
		}
	}
	if s.DurationSeconds < ComposeLintMinDurationSeconds {
		v = append(v, fmt.Sprintf("duration_seconds %d < %d", s.DurationSeconds, ComposeLintMinDurationSeconds))
	}
	switch s.Confidence.Level {
	case sidecar.ConfidenceHigh, sidecar.ConfidenceModerate:
		// ok
	case "":
		v = append(v, "confidence.level not set")
	default:
		v = append(v, fmt.Sprintf("confidence.level %q below moderate (see confidence.factors)", s.Confidence.Level))
	}
	if len(s.CoverageWarnings) > 0 {
		v = append(v, fmt.Sprintf("coverage_warnings non-empty (%d entries; entrypoint-expected caps not covered)", len(s.CoverageWarnings)))
	}
	if s.TraceHealth.DropRate >= ComposeLintMaxDropRate {
		v = append(v, fmt.Sprintf("trace_health.drop_rate %.4f >= %.2f", s.TraceHealth.DropRate, ComposeLintMaxDropRate))
	}
	if len(s.Target.ReplicaCapDisagreement) > 0 {
		v = append(v, fmt.Sprintf("replica_cap_disagreement non-empty (%d caps disagree across replicas)", len(s.Target.ReplicaCapDisagreement)))
	}
	return v
}

// ComposeLintImage returns the catalog match key: the canonical repository
// reference for the observed image, registry+namespace normalized to their
// Docker defaults, with any tag and digest stripped. Mirrors compose-lint's
// normalize_repository (src/compose_lint/profiles/refs.py) so csd's `image:`
// field matches the same profile the loader keys on. Empty image ref falls back
// to "unknown" -- the profile can still be edited by hand before landing in a
// PR; refusing to emit here would hide the violation output.
func ComposeLintImage(s *sidecar.Sidecar) string {
	if s.Image == "" {
		return "unknown"
	}
	return normalizeRepository(stripTagDigest(s.Image))
}

// composeLintValidatedImage returns the normalized name@digest the dimension
// was derived against (schema requires a digest-pinned validated_image). No
// digest yields a bare name -- but that is already an image_digest contract
// violation, so it only occurs on the exploratory path.
func composeLintValidatedImage(s *sidecar.Sidecar) string {
	img := normalizeRepository(stripTagDigest(s.Image))
	if s.ImageDigest != "" {
		return img + "@" + s.ImageDigest
	}
	return img
}

// stripTagDigest removes a trailing @digest and a :tag from an image reference,
// leaving registry/namespace/name. A tag is a ':' in the final path segment, so
// a registry port (localhost:5000/foo) is left intact.
func stripTagDigest(ref string) string {
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	slash := strings.LastIndex(ref, "/")
	if col := strings.LastIndex(ref[slash+1:], ":"); col >= 0 {
		ref = ref[:slash+1+col]
	}
	return ref
}

// normalizeRepository expands a bare image name to its canonical
// registry/namespace/name, mirroring compose-lint's normalize_repository:
//
//	postgres                   -> docker.io/library/postgres
//	linuxserver/radarr         -> docker.io/linuxserver/radarr
//	lscr.io/linuxserver/radarr -> lscr.io/linuxserver/radarr
//	localhost:5000/foo         -> localhost:5000/foo
//
// The first segment is a registry when it contains '.' or ':' or is exactly
// "localhost"; otherwise the ref is a docker.io ref and a single-name path gets
// the implicit `library/` namespace.
func normalizeRepository(name string) string {
	if name == "" {
		return name
	}
	first, rest, hasSlash := strings.Cut(name, "/")
	var registry, path string
	if hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost") {
		registry, path = strings.ToLower(first), rest
	} else {
		registry, path = "docker.io", name
	}
	if registry == "docker.io" && !strings.Contains(path, "/") {
		path = "library/" + path
	}
	return registry + "/" + path
}
