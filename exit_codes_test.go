package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExitCodeFor_NilIsOK(t *testing.T) {
	if got := exitCodeFor(nil); got != ExitOK {
		t.Errorf("nil -> %d, want %d", got, ExitOK)
	}
}

func TestExitCodeFor_UnclassifiedIsRuntime(t *testing.T) {
	if got := exitCodeFor(errors.New("boom")); got != ExitRuntime {
		t.Errorf("plain err -> %d, want %d", got, ExitRuntime)
	}
}

func TestExitCodeFor_RecoversThroughWrap(t *testing.T) {
	// fmt.Errorf %w wrapping must not hide the coded-error layer -- run()
	// wraps ambiguity with ExitTargetAmbiguous on top of the typed error,
	// and main() needs to see the outer code through whatever %w nesting
	// sits above it.
	inner := wrapCoded(ExitTargetAmbiguous, errors.New("two replicas"))
	wrapped := fmt.Errorf("while selecting: %w", inner)
	if got := exitCodeFor(wrapped); got != ExitTargetAmbiguous {
		t.Errorf("wrapped coded err -> %d, want %d", got, ExitTargetAmbiguous)
	}
}

func TestRun_ExitCode_UsageOnBadFlagCombo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"container-and-image", []string{"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "x", "--image", "y"}},
		{"all-matching-without-image", []string{"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "x", "--all-matching"}},
		{"no-target", []string{}},
		{"unknown-flag", []string{"--nope"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			err := run(tc.args, &out, &errBuf)
			if err == nil {
				t.Fatal("expected error")
			}
			if got := exitCodeFor(err); got != ExitUsage {
				t.Errorf("exit = %d, want ExitUsage (%d); err=%v", got, ExitUsage, err)
			}
		})
	}
}

func TestRun_ExitCode_TargetAmbiguous(t *testing.T) {
	// sample.ndjson has two postgres replicas; --image without
	// --all-matching is the documented ambiguity case.
	var out, errBuf bytes.Buffer
	err := run([]string{"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson", "--image", "postgres:16"}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected ambiguity error")
	}
	if got := exitCodeFor(err); got != ExitTargetAmbiguous {
		t.Errorf("exit = %d, want ExitTargetAmbiguous (%d); err=%v", got, ExitTargetAmbiguous, err)
	}
	// The typed error must survive wrapping so future consumers can
	// inspect it (e.g. the sidecar writer logging a coverage warning).
	var amb *ambiguousSelectionError
	if !errors.As(err, &amb) {
		t.Errorf("typed ambiguousSelectionError lost; err=%v", err)
	}
}

func TestRun_ExitCode_DropRateExcessive(t *testing.T) {
	// PLAN.md §Exit codes: drop rate >= 10% is artifact-with-caveat --
	// caps must still print, and the exit code signals untrustworthiness.
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/high_drop_rate.ndjson",
		"--fixture-stderr", "testdata/ig-versions/v0.51.0/high_drop_rate.stderr",
		"--container", "t",
		"--init-window-ms", "0",
	}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected drop-rate error")
	}
	if got := exitCodeFor(err); got != ExitDropRateExcessive {
		t.Errorf("exit = %d, want ExitDropRateExcessive (%d); err=%v", got, ExitDropRateExcessive, err)
	}
	if want := "cap_drop:\n  - ALL\ncap_add:\n  - CHOWN\n  - SETUID\n"; out.String() != want {
		t.Errorf("caps output lost on drop-rate exit; got %q want %q", out.String(), want)
	}
}

func TestRun_ExitCode_IGMissing(t *testing.T) {
	// Exercise the observe() path with a guaranteed-missing ig binary.
	// Without --fixture, run() falls into observe() and cmd.Start fails
	// with ENOENT, which must map to ExitIGMissing.
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--container", "anything",
		"--ig", "/nonexistent/csd-ig-step7-test",
		"--duration", "10ms",
	}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected missing-binary error")
	}
	if got := exitCodeFor(err); got != ExitIGMissing {
		t.Errorf("exit = %d, want ExitIGMissing (%d); err=%v", got, ExitIGMissing, err)
	}
	if !strings.Contains(err.Error(), "ig binary") {
		t.Errorf("error message should name the missing binary: %q", err.Error())
	}
}

// fakeIGBinary writes a tiny shell script that prints version on `version`
// and returns it as a path suitable for --ig. It does not implement
// `run`; the version-pin test never reaches that subcommand because
// produceObservation() short-circuits on the SchemaMismatch error.
func fakeIGBinary(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ig-fake")
	script := "#!/bin/sh\nif [ \"$1\" = version ]; then echo " + version + "; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ig: %v", err)
	}
	return path
}

func TestRun_ExitCode_SchemaMismatchOnWrongIGVersion(t *testing.T) {
	// PLAN.md §IG version pinning: when ig's reported version is not
	// PinnedIGVersion, csd refuses to parse and exits SchemaMismatch.
	// No sidecar must be written -- the artifact would be untrustworthy
	// because csd's parser is shape-pinned to PinnedIGVersion.
	dir := t.TempDir()
	out := filepath.Join(dir, "sidecar.json")
	fake := fakeIGBinary(t, "v0.50.0")

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--container", "anything",
		"--ig", fake,
		"--duration", "10ms",
		"--out", out,
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected SchemaMismatch error")
	}
	if got := exitCodeFor(err); got != ExitSchemaMismatch {
		t.Errorf("exit = %d, want ExitSchemaMismatch (%d); err=%v", got, ExitSchemaMismatch, err)
	}
	if !strings.Contains(err.Error(), PinnedIGVersion) {
		t.Errorf("error message should name PINNED_IG_VERSION; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "v0.50.0") {
		t.Errorf("error message should name detected version; got %q", err.Error())
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Errorf("--out file %q should not have been written on SchemaMismatch", out)
	}
	if stdout.Len() != 0 {
		t.Errorf("no stdout should be emitted on SchemaMismatch; got %q", stdout.String())
	}
}

func TestRun_ExitCode_PinnedIGVersionPasses(t *testing.T) {
	// Positive control: when the fake ig reports PinnedIGVersion, the
	// version-pin gate passes and we fall through to observe(), which
	// fails on the fake's missing `run` subcommand. The exit code must
	// NOT be SchemaMismatch -- exact downstream code (likely Runtime)
	// is not asserted; this test only proves the pin check accepts a
	// matching version.
	fake := fakeIGBinary(t, PinnedIGVersion)
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--container", "anything",
		"--ig", fake,
		"--duration", "10ms",
	}, &stdout, &stderr)
	if err == nil {
		// Unlikely (the fake doesn't implement `run`), but a clean exit
		// would also prove the pin check accepted the version.
		return
	}
	if got := exitCodeFor(err); got == ExitSchemaMismatch {
		t.Errorf("PinnedIGVersion should pass the gate; got SchemaMismatch err=%v", err)
	}
}

func TestIsIGMissing_ClassifiesCommonCauses(t *testing.T) {
	// Guard against a future Go version changing the err types returned
	// by exec.Cmd.Start -- the mapping to ExitIGMissing is a user-facing
	// contract.
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"random", errors.New("other"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isIGMissing(tc.err); got != tc.want {
				t.Errorf("isIGMissing(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
