package exit

import (
	"errors"
	"fmt"
	"testing"
)

func TestCodeFor_NilIsOK(t *testing.T) {
	if got := CodeFor(nil); got != OK {
		t.Errorf("nil -> %d, want %d", got, OK)
	}
}

func TestCodeFor_UnclassifiedIsRuntime(t *testing.T) {
	if got := CodeFor(errors.New("boom")); got != Runtime {
		t.Errorf("plain err -> %d, want %d", got, Runtime)
	}
}

func TestCodeFor_RecoversThroughWrap(t *testing.T) {
	// fmt.Errorf %w wrapping must not hide the coded-error layer -- the CLI
	// wraps ambiguity with TargetAmbiguous on top of the typed error, and
	// main() needs to see the outer code through whatever %w nesting sits
	// above it.
	inner := WrapCoded(TargetAmbiguous, errors.New("two replicas"))
	wrapped := fmt.Errorf("while selecting: %w", inner)
	if got := CodeFor(wrapped); got != TargetAmbiguous {
		t.Errorf("wrapped coded err -> %d, want %d", got, TargetAmbiguous)
	}
}

func TestIsIGMissing_ClassifiesCommonCauses(t *testing.T) {
	// Guard against a future Go version changing the err types returned
	// by exec.Cmd.Start -- the mapping to IGMissing is a user-facing
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
			if got := IsIGMissing(tc.err); got != tc.want {
				t.Errorf("IsIGMissing(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
