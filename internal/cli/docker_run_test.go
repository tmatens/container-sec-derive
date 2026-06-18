package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/format"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestWriteDockerRun_StandardCapSet(t *testing.T) {
	s := sidecar.NewSidecar()
	s.Capabilities = []sidecar.Capability{
		{Name: "CHOWN"},
		{Name: "DAC_OVERRIDE"},
		{Name: "SETUID"},
	}
	var buf bytes.Buffer
	if err := format.WriteDockerRun(&buf, s); err != nil {
		t.Fatalf("format.WriteDockerRun: %v", err)
	}
	want := "--cap-drop=ALL --cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=SETUID\n"
	if buf.String() != want {
		t.Errorf("docker-run output mismatch:\ngot:  %q\nwant: %q", buf.String(), want)
	}
}

func TestWriteDockerRun_EmptyCapSetOmitsCapAdd(t *testing.T) {
	// Mirror format.WriteCompose: the "drop everything, add nothing" shape is
	// --cap-drop=ALL alone. Emitting a bare `--cap-add=` or an empty token
	// would be a docker-run syntax error, so the formatter must elide.
	s := sidecar.NewSidecar()
	var buf bytes.Buffer
	if err := format.WriteDockerRun(&buf, s); err != nil {
		t.Fatalf("format.WriteDockerRun: %v", err)
	}
	if got, want := buf.String(), "--cap-drop=ALL\n"; got != want {
		t.Errorf("empty cap set output mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestWriteDockerRun_PreservesAggregatorOrder(t *testing.T) {
	// The aggregator sorts caps ascending; the formatter must not reorder
	// them. Downstream diffing across digest bumps relies on stable order.
	s := sidecar.NewSidecar()
	s.Capabilities = []sidecar.Capability{
		{Name: "A"}, {Name: "B"}, {Name: "C"},
	}
	var buf bytes.Buffer
	if err := format.WriteDockerRun(&buf, s); err != nil {
		t.Fatalf("format.WriteDockerRun: %v", err)
	}
	if got, want := buf.String(), "--cap-drop=ALL --cap-add=A --cap-add=B --cap-add=C\n"; got != want {
		t.Errorf("order mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestRun_DockerRunFormatEndToEnd(t *testing.T) {
	// End-to-end: --format docker-run must route through the dispatch in
	// Run() and produce the flag string on stdout. This is the only place
	// that catches a main.go wiring regression where the switch falls
	// through and silently writes compose instead.
	var out, errBuf bytes.Buffer
	err := Run([]string{
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "docker-run",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	if !strings.HasPrefix(out.String(), "--cap-drop=ALL") {
		t.Errorf("expected docker-run flag output, got:\n%s", out.String())
	}
	// Must not contain compose-style markers -- cheapest guard against the
	// dispatch silently falling back to compose.
	if strings.Contains(out.String(), "cap_drop:") {
		t.Errorf("docker-run output leaked compose YAML:\n%s", out.String())
	}
}
