package sidecar

import (
	"strconv"
	"strings"
)

// Schema-version compatibility. SchemaVersion follows semver-on-schema: additive
// changes stay within a major (a document is forward/backward compatible across
// minors), while a new major is a breaking change a consumer must reject
// (PLAN.md §Output schema "Schema evolution policy"). These helpers are the one
// place that boundary is computed, so both the verify sidecar-loader and the
// compose-lint-profile acceptance contract share it — and it is derived from the
// SchemaVersion constant rather than a hand-written "1." literal, so bumping the
// schema to a new major automatically moves the boundary with no call-site edits.

// schemaMajor parses the major-version component of a schema_version string
// ("1.5" -> 1). ok is false for an empty or non-numeric leading component, so a
// missing / garbage version is distinguishable from a real major.
func schemaMajor(v string) (major int, ok bool) {
	lead := v
	if i := strings.IndexByte(v, '.'); i >= 0 {
		lead = v[:i]
	}
	n, err := strconv.Atoi(lead)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// CurrentSchemaMajor is the schema major this binary speaks — the major of
// SchemaVersion. SchemaVersion is a well-formed constant, so parsing never
// fails.
func CurrentSchemaMajor() int {
	m, _ := schemaMajor(SchemaVersion)
	return m
}

// SchemaMajorCompatible reports whether a sidecar's schema_version shares this
// binary's schema major and is therefore safe to consume. An empty or
// unparseable version is not compatible — an unknown-shaped document must not be
// consumed leniently.
func SchemaMajorCompatible(version string) bool {
	m, ok := schemaMajor(version)
	return ok && m == CurrentSchemaMajor()
}
