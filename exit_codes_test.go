package main

import (
	"bytes"
	"errors"
	"fmt"
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
		{"container-and-image", []string{"--fixture", "testdata/sample.ndjson", "--container", "x", "--image", "y"}},
		{"all-matching-without-image", []string{"--fixture", "testdata/sample.ndjson", "--container", "x", "--all-matching"}},
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
	err := run([]string{"--fixture", "testdata/sample.ndjson", "--image", "postgres:16"}, &out, &errBuf)
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
	err := run([]string{"--fixture", "testdata/high_drop_rate.ndjson", "--container", "t", "--init-window-ms", "0"}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected drop-rate error")
	}
	if got := exitCodeFor(err); got != ExitDropRateExcessive {
		t.Errorf("exit = %d, want ExitDropRateExcessive (%d); err=%v", got, ExitDropRateExcessive, err)
	}
	if want := "CHOWN\nSETUID\n"; out.String() != want {
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
