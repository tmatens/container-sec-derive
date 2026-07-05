package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/ig"
)

func TestRun_ExitCode_UsageOnBadFlagCombo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"container-and-image", []string{"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "x", "--image", "y"}},
		{"all-matching-without-image", []string{"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson", "--container", "x", "--all-matching"}},
		{"no-target", []string{}},
		{"unknown-flag", []string{"--nope"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			err := Run(tc.args, &out, &errBuf)
			if err == nil {
				t.Fatal("expected error")
			}
			if got := exit.CodeFor(err); got != exit.Usage {
				t.Errorf("exit = %d, want Usage (%d); err=%v", got, exit.Usage, err)
			}
		})
	}
}

func TestRun_BadFlag_NoDuplicateOutput(t *testing.T) {
	// #291: Run must not print the flag package's own error/usage on a parse
	// error -- main() prefixes the single "csd: <err>" line. Run's stderr must
	// therefore stay empty; the error still carries EX_USAGE.
	var out, errBuf bytes.Buffer
	err := Run([]string{"--nope"}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if got := exit.CodeFor(err); got != exit.Usage {
		t.Errorf("exit = %d, want Usage (%d)", got, exit.Usage)
	}
	if errBuf.Len() != 0 {
		t.Errorf("Run wrote to stderr on parse error (duplicate of main's line):\n%s", errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("Run wrote to stdout on parse error:\n%s", out.String())
	}
}

func TestRun_HelpPrintsUsageAndExitsClean(t *testing.T) {
	// #291: -h/--help is an explicit request, not a usage error -- usage goes to
	// stdout and Run returns nil (no "csd: flag: help requested" line).
	for _, arg := range []string{"-h", "--help"} {
		var out, errBuf bytes.Buffer
		if err := Run([]string{arg}, &out, &errBuf); err != nil {
			t.Errorf("%s: want nil error, got %v", arg, err)
		}
		if !strings.Contains(out.String(), "-container") {
			t.Errorf("%s: usage should list flags on stdout, got:\n%s", arg, out.String())
		}
	}
}

func TestRun_ExitCode_TargetAmbiguous(t *testing.T) {
	// sample.ndjson has two postgres replicas; --image without
	// --all-matching is the documented ambiguity case.
	var out, errBuf bytes.Buffer
	err := Run([]string{"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson", "--image", "postgres:16"}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected ambiguity error")
	}
	if got := exit.CodeFor(err); got != exit.TargetAmbiguous {
		t.Errorf("exit = %d, want TargetAmbiguous (%d); err=%v", got, exit.TargetAmbiguous, err)
	}
	// The typed error must survive wrapping so future consumers can
	// inspect it (e.g. the sidecar writer logging a coverage warning).
	var amb *exit.AmbiguousSelectionError
	if !errors.As(err, &amb) {
		t.Errorf("typed AmbiguousSelectionError lost; err=%v", err)
	}
}

func TestRun_ExitCode_DropRateExcessive(t *testing.T) {
	// PLAN.md §Exit codes: drop rate >= 10% is artifact-with-caveat --
	// caps must still print, and the exit code signals untrustworthiness.
	var out, errBuf bytes.Buffer
	err := Run([]string{
		"--fixture", "../../testdata/ig-versions/v0.51.0/high_drop_rate.ndjson",
		"--fixture-stderr", "../../testdata/ig-versions/v0.51.0/high_drop_rate.stderr",
		"--container", "t",
		"--init-window-ms", "0",
	}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected drop-rate error")
	}
	if got := exit.CodeFor(err); got != exit.DropRateExcessive {
		t.Errorf("exit = %d, want DropRateExcessive (%d); err=%v", got, exit.DropRateExcessive, err)
	}
	if want := "cap_drop:\n  - ALL\ncap_add:\n  - CHOWN\n  - SETUID\n"; out.String() != want {
		t.Errorf("caps output lost on drop-rate exit; got %q want %q", out.String(), want)
	}
}

func TestRun_ExitCode_IGMissing(t *testing.T) {
	// Exercise the observe() path with a guaranteed-missing ig binary.
	// Without --fixture, Run() falls into observe() and cmd.Start fails
	// with ENOENT, which must map to IGMissing.
	var out, errBuf bytes.Buffer
	err := Run([]string{
		"--container", "anything",
		"--ig", "/nonexistent/csd-ig-step7-test",
		"--duration", "10ms",
	}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected missing-binary error")
	}
	if got := exit.CodeFor(err); got != exit.IGMissing {
		t.Errorf("exit = %d, want IGMissing (%d); err=%v", got, exit.IGMissing, err)
	}
	if !strings.Contains(err.Error(), "ig binary") {
		t.Errorf("error message should name the missing binary: %q", err.Error())
	}
}

// fakeIGBinary writes a tiny shell script that prints version on `version`
// and returns it as a path suitable for --ig. It does not implement
// `run`; the version-pin test never reaches that subcommand because
// ProduceObservation() short-circuits on the SchemaMismatch error.
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
	err := Run([]string{
		"--container", "anything",
		"--ig", fake,
		"--duration", "10ms",
		"--out", out,
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected SchemaMismatch error")
	}
	if got := exit.CodeFor(err); got != exit.SchemaMismatch {
		t.Errorf("exit = %d, want SchemaMismatch (%d); err=%v", got, exit.SchemaMismatch, err)
	}
	if !strings.Contains(err.Error(), ig.PinnedIGVersion) {
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
	fake := fakeIGBinary(t, ig.PinnedIGVersion)
	var stdout, stderr bytes.Buffer
	err := Run([]string{
		"--container", "anything",
		"--ig", fake,
		"--duration", "10ms",
	}, &stdout, &stderr)
	if err == nil {
		// Unlikely (the fake doesn't implement `run`), but a clean exit
		// would also prove the pin check accepted the version.
		return
	}
	if got := exit.CodeFor(err); got == exit.SchemaMismatch {
		t.Errorf("PinnedIGVersion should pass the gate; got SchemaMismatch err=%v", err)
	}
}
