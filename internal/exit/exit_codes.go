// Package exit is the single source of truth for csd's process exit codes
// and the typed errors that carry them. The EX_* contract mirrors PLAN.md
// §Exit codes; that table is the user-facing contract, this package is the
// in-code authority. Drift between the two is a bug -- CI integrators read
// the code from `$?`.
//
// It is a foundation leaf: stdlib-only, imported by the observers, the
// attribution layer, and the CLI, and it imports none of them.
package exit

import (
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"strings"
)

// Exit codes mirror PLAN.md §Exit codes. That table is the user-facing
// contract; this file is the single source of truth in code.
//
// Constants for not-yet-reachable codes (TargetExitedEarly) are defined
// here so later steps drop in without renumbering or a parallel constants
// file.
const (
	OK                     = 0
	Runtime                = 1  // unclassified runtime failure; last-resort fallback
	VerifyInsufficient     = 10 // `csd verify` outcome: at least one new denial under the proposed config
	VerifyOverPermissioned = 11 // `csd verify` outcome: profile grants caps the workload never triggers
	TargetExitedEarly      = 20 // reachable once observe() wires restart detection
	DropRateExcessive      = 21
	SchemaMismatch         = 30 // CheckIGVersion returns this when detected ig is not PinnedIGVersion
	IGMissing              = 31
	TargetAmbiguous        = 40
	Usage                  = 64 // EX_USAGE
)

// DropRateAbort is the trace-health drop rate at or above which the
// observation is considered untrustworthy. PLAN.md §Exit codes requires
// a DropRateExcessive return *after* the artifact-with-caveat is still
// emitted, so the caller must print results before surfacing this.
const DropRateAbort = 0.10

// codedError carries an exit code alongside a wrapped error. The CLI
// recovers the code via CodeFor; Error() delegates to the wrapped error so
// "csd: <msg>" formatting stays unchanged.
type codedError struct {
	code int
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }
func (e *codedError) ExitCode() int { return e.code }

// CodedErrorf wraps a formatted message with an exit code.
func CodedErrorf(code int, format string, args ...any) error {
	return &codedError{code: code, err: fmt.Errorf(format, args...)}
}

// WrapCoded attaches an exit code to an existing error.
func WrapCoded(code int, err error) error {
	return &codedError{code: code, err: err}
}

// AmbiguousSelectionError is returned by the aggregators when the target
// selector matched more than one replica without an opt-in to aggregate them:
// a bare --image without --all-matching, or a --container id-prefix that matched
// multiple containers (deep-review M3 — a short prefix used to silently union
// them). A typed error so the CLI can map it to TargetAmbiguous without
// pattern-matching strings.
type AmbiguousSelectionError struct {
	flag     string   // the offending selector flag: "--image" or "--container"
	selector string   // its value
	replicas []string // human-facing "<name> (<id>)" labels, pre-sorted
	// allMatchingHint is true only for --image, where --all-matching is a valid
	// way to aggregate; --all-matching requires --image, so it is not offered as
	// a remedy for an ambiguous --container prefix.
	allMatchingHint bool
}

// NewAmbiguousSelectionError builds the typed ambiguous-selection error. The
// attribution layer decides the flag/hint; this keeps the struct fields
// unexported while letting another package construct the value.
func NewAmbiguousSelectionError(flag, selector string, replicas []string, allMatchingHint bool) *AmbiguousSelectionError {
	return &AmbiguousSelectionError{flag: flag, selector: selector, replicas: replicas, allMatchingHint: allMatchingHint}
}

// Flag is the offending selector flag ("--image" or "--container").
func (e *AmbiguousSelectionError) Flag() string { return e.flag }

// Replicas are the human-facing "<name> (<id>)" labels that matched.
func (e *AmbiguousSelectionError) Replicas() []string { return e.replicas }

// AllMatchingHint reports whether --all-matching is offered as a remedy
// (true only for an ambiguous --image).
func (e *AmbiguousSelectionError) AllMatchingHint() bool { return e.allMatchingHint }

func (e *AmbiguousSelectionError) Error() string {
	remedy := "rerun with a longer or exact --container id to disambiguate"
	if e.allMatchingHint {
		remedy = "rerun with --container to disambiguate or --all-matching to aggregate across replicas"
	}
	return fmt.Sprintf(
		"%s %q matched %d replicas; %s:\n  %s",
		e.flag, e.selector, len(e.replicas), remedy, strings.Join(e.replicas, "\n  "),
	)
}

// IsIGMissing reports whether a `cmd.Start()` error indicates the ig
// binary does not exist or is not executable. PLAN.md §Exit codes lumps
// both under IGMissing -- the distinction doesn't help a CI integrator
// decide what to fix.
func IsIGMissing(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, exec.ErrNotFound) {
		return true
	}
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	return false
}

// CodeFor returns the exit code the CLI should use for err.
func CodeFor(err error) int {
	if err == nil {
		return OK
	}
	var ce *codedError
	if errors.As(err, &ce) {
		return ce.code
	}
	return Runtime
}
