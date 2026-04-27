package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"strings"
)

// Exit codes mirror PLAN.md §Exit codes. That table is the user-facing
// contract; this file is the single source of truth in code. Drift
// between the two is a bug -- CI integrators read the code from `$?`.
//
// v0.1 emits the subset of codes reachable from the surfaces shipped so
// far (21, 31, 40, 64). Constants for not-yet-reachable codes (20, 30)
// are defined here so later steps drop in without renumbering or a
// parallel constants file.
const (
	ExitOK                       = 0
	ExitRuntime                  = 1  // unclassified runtime failure; last-resort fallback
	ExitVerifyInsufficient       = 10 // `csd verify` outcome: at least one new denial under the proposed config
	ExitVerifyOverPermissioned   = 11 // `csd verify` outcome: profile grants caps the workload never triggers
	ExitTargetExitedEarly        = 20 // reachable once observe() wires restart detection
	ExitDropRateExcessive        = 21
	ExitSchemaMismatch           = 30 // reachable once the IG version-pin parser lands
	ExitIGMissing                = 31
	ExitTargetAmbiguous          = 40
	ExitUsage                    = 64 // EX_USAGE
)

// DropRateAbort is the trace-health drop rate at or above which the
// observation is considered untrustworthy. PLAN.md §Exit codes requires
// an ExitDropRateExcessive return *after* the artifact-with-caveat is
// still emitted, so the caller must print results before surfacing this.
const DropRateAbort = 0.10

// codedError carries an exit code alongside a wrapped error. main()
// recovers the code via errors.As(err, &*codedError); Error() delegates
// to the wrapped error so "csd: <msg>" formatting stays unchanged.
type codedError struct {
	code int
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }
func (e *codedError) ExitCode() int { return e.code }

func codedErrorf(code int, format string, args ...any) *codedError {
	return &codedError{code: code, err: fmt.Errorf(format, args...)}
}

func wrapCoded(code int, err error) *codedError {
	return &codedError{code: code, err: err}
}

// ambiguousSelectionError is returned by aggregate() when --image matched
// more than one replica without --all-matching. A typed error so run()
// can map it to ExitTargetAmbiguous without pattern-matching strings.
type ambiguousSelectionError struct {
	image    string
	replicas []string // human-facing "<name> (<id>)" labels, pre-sorted
}

func (e *ambiguousSelectionError) Error() string {
	return fmt.Sprintf(
		"--image %q matched %d replicas; rerun with --container to disambiguate or --all-matching to aggregate across replicas:\n  %s",
		e.image, len(e.replicas), strings.Join(e.replicas, "\n  "),
	)
}

// isIGMissing reports whether a `cmd.Start()` error indicates the ig
// binary does not exist or is not executable. PLAN.md §Exit codes lumps
// both under ExitIGMissing -- the distinction doesn't help a CI
// integrator decide what to fix.
func isIGMissing(err error) bool {
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

// exitCodeFor returns the exit code main() should use for err.
func exitCodeFor(err error) int {
	if err == nil {
		return ExitOK
	}
	var ce *codedError
	if errors.As(err, &ce) {
		return ce.code
	}
	return ExitRuntime
}
