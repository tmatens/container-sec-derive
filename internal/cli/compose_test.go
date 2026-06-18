package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/format"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestWriteCompose_StandardCapSet(t *testing.T) {
	s := sidecar.NewSidecar()
	s.Capabilities = []sidecar.Capability{
		{Name: "CHOWN"},
		{Name: "DAC_OVERRIDE"},
		{Name: "SETUID"},
	}
	var buf bytes.Buffer
	if err := format.WriteCompose(&buf, s); err != nil {
		t.Fatalf("format.WriteCompose: %v", err)
	}
	want := "cap_drop:\n  - ALL\ncap_add:\n  - CHOWN\n  - DAC_OVERRIDE\n  - SETUID\n"
	if buf.String() != want {
		t.Errorf("compose output mismatch:\ngot:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestWriteCompose_EmptyCapSetOmitsCapAdd(t *testing.T) {
	// "Drop everything, add nothing" is a valid compose shape. cap_add with
	// an empty list would be technically legal YAML but semantically noisy;
	// the formatter elides it so reviewers see the signal, not the scaffolding.
	s := sidecar.NewSidecar()
	var buf bytes.Buffer
	if err := format.WriteCompose(&buf, s); err != nil {
		t.Fatalf("format.WriteCompose: %v", err)
	}
	want := "cap_drop:\n  - ALL\n"
	if buf.String() != want {
		t.Errorf("empty cap set output mismatch:\ngot:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestWriteCompose_PreservesAggregatorOrder(t *testing.T) {
	// The aggregator sorts caps ascending; the formatter must not reorder
	// them. If it did, golden tests and downstream diffing would drift.
	s := sidecar.NewSidecar()
	s.Capabilities = []sidecar.Capability{
		{Name: "A"}, {Name: "B"}, {Name: "C"},
	}
	var buf bytes.Buffer
	if err := format.WriteCompose(&buf, s); err != nil {
		t.Fatalf("format.WriteCompose: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	// Last three lines are the cap_add entries.
	wantOrder := []string{"  - A", "  - B", "  - C"}
	for i, want := range wantOrder {
		got := lines[len(lines)-3+i]
		if got != want {
			t.Errorf("line %d = %q, want %q", len(lines)-3+i, got, want)
		}
	}
}

func TestRun_UnknownFormatIsUsageError(t *testing.T) {
	// All v0.1.0-rc formatters are now implemented; an unrecognized
	// value must surface as EX_USAGE with a list of supported formats,
	// not as a silent fall-through.
	var out, errBuf bytes.Buffer
	err := Run([]string{
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "xml",
	}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected usage error for --format xml")
	}
	if code := exit.CodeFor(err); code != exit.Usage {
		t.Errorf("exit code = %d, want %d (exit.Usage)", code, exit.Usage)
	}
	if !strings.Contains(err.Error(), "supported:") {
		t.Errorf("error should list supported formats, got: %v", err)
	}
}

func TestRun_ExplicitComposeFormatWorks(t *testing.T) {
	// `--format compose` is the default, but passing it explicitly must
	// also be accepted (users scripting csd into CI want the knob even
	// when the default would do).
	var out, errBuf bytes.Buffer
	err := Run([]string{
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "compose",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	if !strings.HasPrefix(out.String(), "cap_drop:\n  - ALL\n") {
		t.Errorf("explicit --format compose produced unexpected output:\n%s", out.String())
	}
}
