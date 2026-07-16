package observe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRuntime writes an executable that mimics `docker inspect --format
// {{.Name}} -- <target>` output and returns its path.
func fakeRuntime(t *testing.T, stdout string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-runtime")
	script := "#!/bin/sh\nprintf '%s\\n' '" + stdout + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGadgetContainerFilter(t *testing.T) {
	t.Run("no container target observes host-wide", func(t *testing.T) {
		if got := GadgetContainerFilter("", "docker", nil); got != nil {
			t.Errorf("GadgetContainerFilter(\"\") = %v, want nil", got)
		}
	})

	t.Run("resolved name becomes a --containername filter", func(t *testing.T) {
		rt := fakeRuntime(t, "/csd-capadd-netdata")
		got := GadgetContainerFilter("2af1c0ffee", rt, nil)
		want := "--containername csd-capadd-netdata"
		if strings.Join(got, " ") != want {
			t.Errorf("GadgetContainerFilter = %v, want [%s]", got, want)
		}
	})

	t.Run("resolution failure falls back to host-wide with a note", func(t *testing.T) {
		var sb strings.Builder
		if got := GadgetContainerFilter("gone", "/nonexistent/csd-runtime", &sb); got != nil {
			t.Errorf("GadgetContainerFilter on failing runtime = %v, want nil", got)
		}
		if !strings.Contains(sb.String(), "observing host-wide") {
			t.Errorf("fallback note missing from stderr: %q", sb.String())
		}
	})

	t.Run("empty resolved name observes host-wide", func(t *testing.T) {
		rt := fakeRuntime(t, "")
		if got := GadgetContainerFilter("x", rt, nil); got != nil {
			t.Errorf("GadgetContainerFilter with empty name = %v, want nil", got)
		}
	})
}
