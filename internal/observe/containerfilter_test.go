package observe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeExec writes an executable that prints stdout and returns its path.
func fakeExec(t *testing.T, stdout string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-exec")
	script := "#!/bin/sh\nprintf '%s\\n' '" + stdout + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

const testID = "38da087371c7dafa48f79816cf8c10cac7af1c2aa65b488d884dc13d073484a0"

func TestGadgetContainerFilter(t *testing.T) {
	igKnows := fakeExec(t, `[{"runtime":{"containerName":"csd-smoke-synthetic","containerId":"`+testID+`"}}]`)

	t.Run("no container target observes host-wide", func(t *testing.T) {
		if got := GadgetContainerFilter("", "docker", igKnows, nil); got != nil {
			t.Errorf("GadgetContainerFilter(\"\") = %v, want nil", got)
		}
	})

	t.Run("filter uses IG's own name for the resolved id", func(t *testing.T) {
		rt := fakeExec(t, testID)
		got := GadgetContainerFilter("csd-smoke", rt, igKnows, nil)
		want := "--containername csd-smoke-synthetic"
		if strings.Join(got, " ") != want {
			t.Errorf("GadgetContainerFilter = %v, want [%s]", got, want)
		}
	})

	t.Run("runtime resolution failure falls back to host-wide with a note", func(t *testing.T) {
		var sb strings.Builder
		if got := GadgetContainerFilter("gone", "/nonexistent/csd-runtime", igKnows, &sb); got != nil {
			t.Errorf("GadgetContainerFilter on failing runtime = %v, want nil", got)
		}
		if !strings.Contains(sb.String(), "observing host-wide") {
			t.Errorf("fallback note missing from stderr: %q", sb.String())
		}
	})

	t.Run("ig lookup failure falls back to host-wide with a note", func(t *testing.T) {
		rt := fakeExec(t, testID)
		var sb strings.Builder
		if got := GadgetContainerFilter("x", rt, "/nonexistent/csd-ig", &sb); got != nil {
			t.Errorf("GadgetContainerFilter on failing ig = %v, want nil", got)
		}
		if !strings.Contains(sb.String(), "observing host-wide") {
			t.Errorf("fallback note missing from stderr: %q", sb.String())
		}
	})

	t.Run("target absent from ig's view falls back to host-wide", func(t *testing.T) {
		// Regression for the hosted-runner smoke failure: the runtime resolves
		// the container, but IG's container view does not include it (Docker
		// 29 containerd image store); a docker-derived name filter would match
		// nothing and observe zero events. Must fall back, not filter.
		rt := fakeExec(t, testID)
		igEmpty := fakeExec(t, "[]")
		var sb strings.Builder
		if got := GadgetContainerFilter("x", rt, igEmpty, &sb); got != nil {
			t.Errorf("GadgetContainerFilter with unknown-to-ig target = %v, want nil", got)
		}
		if !strings.Contains(sb.String(), "not in ig's container view") {
			t.Errorf("fallback note missing from stderr: %q", sb.String())
		}
	})
}
