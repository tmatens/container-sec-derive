package format

import (
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestWriteFSCompose(t *testing.T) {
	t.Run("read_only only when no rootfs writes", func(t *testing.T) {
		var b strings.Builder
		if err := WriteFSCompose(&b, sidecar.FSRecommendation{ReadOnly: true}); err != nil {
			t.Fatal(err)
		}
		if got := b.String(); got != "read_only: true\n" {
			t.Errorf("got %q, want just read_only: true", got)
		}
	})

	t.Run("read_only + tmpfs list", func(t *testing.T) {
		var b strings.Builder
		rec := sidecar.FSRecommendation{ReadOnly: true, TmpfsPaths: []string{"/var/log/postgresql", "/var/run/postgresql"}}
		if err := WriteFSCompose(&b, rec); err != nil {
			t.Fatal(err)
		}
		out := b.String()
		for _, want := range []string{
			"read_only: true\n",
			"tmpfs:\n",
			"  - /var/log/postgresql\n",
			"  - /var/run/postgresql\n",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("output missing %q\n--- got ---\n%s", want, out)
			}
		}
		// The review note must be a YAML comment so the stanza stays paste-ready.
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if strings.Contains(line, "review") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				t.Errorf("review note is not a comment: %q", line)
			}
		}
		// read_only must precede tmpfs.
		if strings.Index(out, "read_only") > strings.Index(out, "tmpfs:") {
			t.Error("read_only should precede tmpfs")
		}
	})
}
