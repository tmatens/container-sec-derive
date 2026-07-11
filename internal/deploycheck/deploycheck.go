// Package deploycheck is the `csd deploy-check` subcommand: the first-class
// surface for csd's re-derive-at-deploy mode (issue #355).
//
// It productizes the pipeline that scripts/compose_derive.sh already
// implements -- take a service's *real committed compose* (image, user:,
// command, mounts), re-derive its minimum capability set by drop-testing it
// under its own invocation, and diff that minimum against the cap_add the
// compose declares. Because the invocation is the input, the answer is correct
// for *this* deployment: postgres:16 needs [DAC_OVERRIDE, SETGID, SETUID] under
// the default root entrypoint and [] under `user: "999"`, and a name-matched
// catalog profile cannot express either (docs/re-derive-at-deploy.md).
//
// # Thin wrapper, by decision (issue #355 fork 1)
//
// This command does NOT re-implement the pipeline in Go. The derivation's
// trial layer (scripts/drop_test.sh) restarts real containers under varied cap
// sets on a posture-matched host -- it only ever runs on the self-hosted BPF
// runner, so porting it to Go would buy no testability. The compose-parse and
// verdict layers are pure Python (compose_to_spec.py / compose_verdict.py) that
// are already hermetically covered by compose_derive_selftest.sh; re-deriving
// them in Go would either pull a YAML runtime dep into a root-equivalent binary
// (forbidden without discussion -- see CLAUDE.md) or risk silently diverging
// from the tested oracle. So the boundary is: Go owns flags -> invoke
// compose_derive.sh -> exit-code map + evidence-JSON passthrough; shell/python
// owns compose parse -> build -> trials -> verdict. csd already shells out to
// ig/docker rather than linking, so this matches the repo's grain.
//
// # csd verify vs csd deploy-check (issue #355 fork 2)
//
// Kept as siblings, not unified: verify classifies an observation sidecar
// against a baseline sidecar (pure Go, hermetic, fast); deploy-check derives a
// fresh minimum from live drop-test trials and diffs it against declared
// compose config (live, docker-bound, minutes per service). Their inputs are
// different universes and their evidence artifacts carry different fields; the
// shared verdict vocabulary and the parallel exit-code numbering are a
// documentation contract, not shared code.
package deploycheck

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/tmatens/container-sec-derive/internal/exit"
)

// deriveScript is the pipeline entry point this subcommand wraps. It lives in
// the repo tree (not the binary), so the command resolves --script-dir to find
// it -- see resolveScript.
const deriveScript = "compose_derive.sh"

// RunDeployCheck is the entry point for `csd deploy-check`. It derives the
// minimum capability set for one service under its committed compose and diffs
// it against what the compose declares.
//
//	csd deploy-check --compose docker-compose.yml --service immich-db
//
// Compose file + service in; the drop_test evidence JSON (with a deploy_check
// block: recommended / declared / verdict / drop / add) out on stdout, and a
// one-line verdict + progress on stderr. Exit codes distinguish "couldn't
// derive" (DeployCheckCannotRun) from a security verdict (see mapExit).
func RunDeployCheck(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("csd deploy-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		compose     = fs.String("compose", "", "path to the service's committed compose file to derive against (required)")
		service     = fs.String("service", "", "name of the service under services: to derive and diff (required)")
		correctness = fs.String("correctness", "", "path to a per-service correctness check (app-tier oracle); default is the built-in generic still-running check")
		out         = fs.String("out", "", "also write the evidence JSON to this file (stdout still prints it)")
		scriptDir   = fs.String("script-dir", "scripts", "directory holding csd's compose_derive.sh (deploy-check runs from a repo checkout on the derive host)")
		enforce     = fs.Bool("enforce", false, "also fail (non-zero) on not_minimized / over_permissioned; by default only under_permissioned and cannot-run are non-zero")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return exit.WrapCoded(exit.Usage, err)
	}
	if *compose == "" || *service == "" {
		return exit.CodedErrorf(exit.Usage, "csd deploy-check requires --compose <path> and --service <name>")
	}
	if _, err := os.Stat(*compose); err != nil {
		return exit.WrapCoded(exit.Usage, fmt.Errorf("--compose %q: %w", *compose, err))
	}

	script, err := resolveScript(*scriptDir)
	if err != nil {
		return err
	}

	// Shell out to the pipeline for this one service. The evidence JSON is
	// captured (stdout) so we can echo it to our stdout and --out; progress +
	// the one-line verdict stream straight through to stderr, matching how
	// deploy_check.sh leaves the child's stderr un-redirected.
	var evidence bytes.Buffer
	cmd := exec.Command("bash", script, *compose, *service) //nolint:gosec // script path is repo-resolved; compose/service are the user's own inputs to a derivation they invoked
	cmd.Stdout = &evidence
	cmd.Stderr = stderr
	cmd.Env = childEnv(*correctness)

	runErr := cmd.Run()
	code := childExitCode(runErr)
	if code < 0 {
		// The child never produced an exit status (couldn't start bash, etc.).
		// That is a cannot-derive condition, not a security verdict.
		return exit.WrapCoded(exit.DeployCheckCannotRun, fmt.Errorf("run %s: %w", deriveScript, runErr))
	}

	// The verdict path (0/10/11/12) prints evidence JSON on stdout; the
	// failure paths (build/drop-test/spec) print only to stderr, so guard on a
	// non-empty buffer before emitting.
	if evidence.Len() > 0 {
		if _, werr := stdout.Write(evidence.Bytes()); werr != nil {
			return fmt.Errorf("write evidence: %w", werr)
		}
		if *out != "" {
			if werr := writeEvidence(*out, evidence.Bytes()); werr != nil {
				return fmt.Errorf("write --out %q: %w", *out, werr)
			}
		}
	}

	return mapExit(code, *enforce)
}

// resolveScript locates compose_derive.sh under dir and returns its path. csd
// ships as a static binary but the pipeline scripts live in the repo tree, so
// the derive host must run from a checkout (as deploy-check.yml does via
// actions/checkout). Default dir is cwd-relative "scripts"; --script-dir
// overrides. A missing script is a usage error with a pointed remedy rather
// than a cryptic bash "No such file".
func resolveScript(dir string) (string, error) {
	path := filepath.Join(dir, deriveScript)
	if _, err := os.Stat(path); err != nil {
		return "", exit.CodedErrorf(exit.Usage,
			"%s not found under %q: deploy-check runs the csd pipeline scripts from a repo checkout; pass --script-dir <path-to-csd-scripts> (looked for %s)",
			deriveScript, dir, path)
	}
	return path, nil
}

// childEnv builds the environment for compose_derive.sh: the current
// environment plus CORRECTNESS when the caller supplied a per-service oracle.
// PY is left to the script's own python3 default.
func childEnv(correctness string) []string {
	env := os.Environ()
	if correctness != "" {
		env = append(env, "CORRECTNESS="+correctness)
	}
	return env
}

// childExitCode extracts the process exit code from cmd.Run()'s error. nil
// means the child exited 0; an *exec.ExitError carries the real code; any other
// error (couldn't start) yields -1 so the caller can distinguish "never ran".
func childExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// mapExit turns compose_derive.sh's exit code into csd's exit contract.
//
//   - 0  matches                -> OK
//   - 12 under_permissioned     -> always non-zero: a needed cap is undeclared,
//     so the hardened deploy would break. The one verdict that is dangerous by
//     default, so it is a hard red regardless of --enforce.
//   - 10 not_minimized / 11 over_permissioned -> advisory (exit 0) by default;
//     --enforce escalates them to non-zero for CD that rejects any drift.
//   - 3  cannot-run (build / drop-test failure) -> DeployCheckCannotRun, always
//     non-zero and distinct from a verdict (the issue's cannot-run split).
//   - anything else (e.g. 1, a spec error) -> Runtime.
func mapExit(code int, enforce bool) error {
	switch code {
	case exit.OK:
		return nil
	case exit.DeployCheckUnderPermissioned:
		return exit.CodedErrorf(exit.DeployCheckUnderPermissioned,
			"deploy-check: under_permissioned — a needed capability is undeclared; the hardened deploy would break (see the deploy_check evidence above)")
	case exit.DeployCheckNotMinimized:
		if enforce {
			return exit.CodedErrorf(exit.DeployCheckNotMinimized, "deploy-check: not_minimized — a stricter posture is available (--enforce)")
		}
		return nil
	case exit.DeployCheckOverPermissioned:
		if enforce {
			return exit.CodedErrorf(exit.DeployCheckOverPermissioned, "deploy-check: over_permissioned — the compose grants a capability the service never used (--enforce)")
		}
		return nil
	case exit.DeployCheckCannotRun:
		return exit.CodedErrorf(exit.DeployCheckCannotRun, "deploy-check: could not derive %s's minimum (build or drop-test failed; see stderr above)", "the service")
	default:
		return exit.CodedErrorf(exit.Runtime, "deploy-check: derivation failed (compose_derive.sh exited %d)", code)
	}
}

// writeEvidence mirrors the sidecar-write posture in internal/cli: 0600,
// because the evidence is written by a root-equivalent process and should not
// be world- or group-readable.
func writeEvidence(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
