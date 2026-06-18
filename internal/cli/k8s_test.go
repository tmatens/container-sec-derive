package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/format"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestWriteK8s_StandardCapSet(t *testing.T) {
	s := sidecar.NewSidecar()
	s.Capabilities = []sidecar.Capability{
		{Name: "CHOWN"},
		{Name: "DAC_OVERRIDE"},
		{Name: "SETUID"},
	}
	var buf bytes.Buffer
	if err := format.WriteK8s(&buf, s); err != nil {
		t.Fatalf("format.WriteK8s: %v", err)
	}
	want := "securityContext:\n" +
		"  capabilities:\n" +
		"    drop:\n" +
		"      - ALL\n" +
		"    add:\n" +
		"      - CHOWN\n" +
		"      - DAC_OVERRIDE\n" +
		"      - SETUID\n"
	if buf.String() != want {
		t.Errorf("k8s output mismatch:\ngot:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestWriteK8s_EmptyCapSetOmitsAdd(t *testing.T) {
	// Mirror format.WriteCompose / format.WriteDockerRun: "drop everything, add nothing"
	// is a valid k8s shape. An empty `add:` key would be legal YAML but
	// semantically noisy; the formatter elides it so reviewers see the
	// signal, not scaffolding.
	s := sidecar.NewSidecar()
	var buf bytes.Buffer
	if err := format.WriteK8s(&buf, s); err != nil {
		t.Fatalf("format.WriteK8s: %v", err)
	}
	want := "securityContext:\n" +
		"  capabilities:\n" +
		"    drop:\n" +
		"      - ALL\n"
	if buf.String() != want {
		t.Errorf("empty cap set output mismatch:\ngot:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestWriteK8s_PreservesAggregatorOrder(t *testing.T) {
	// The aggregator sorts caps ascending; the formatter must not reorder
	// them. Downstream diffing across digest bumps relies on stable order.
	s := sidecar.NewSidecar()
	s.Capabilities = []sidecar.Capability{
		{Name: "A"}, {Name: "B"}, {Name: "C"},
	}
	var buf bytes.Buffer
	if err := format.WriteK8s(&buf, s); err != nil {
		t.Fatalf("format.WriteK8s: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	wantOrder := []string{"      - A", "      - B", "      - C"}
	for i, want := range wantOrder {
		got := lines[len(lines)-3+i]
		if got != want {
			t.Errorf("line %d = %q, want %q", len(lines)-3+i, got, want)
		}
	}
}

func TestRun_K8sFormatEndToEnd(t *testing.T) {
	// End-to-end: --format k8s must route through Run()'s dispatch and
	// produce the securityContext block on stdout. Guards against a
	// main.go wiring regression where the switch silently falls back
	// to compose.
	var out, errBuf bytes.Buffer
	err := Run([]string{
		"--fixture", "../../testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "k8s",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	if !strings.HasPrefix(out.String(), "securityContext:\n  capabilities:\n") {
		t.Errorf("expected k8s securityContext output, got:\n%s", out.String())
	}
	// Must not contain compose/docker-run markers -- cheapest guard
	// against dispatch falling through to another formatter.
	if strings.HasPrefix(out.String(), "cap_drop:") {
		t.Errorf("k8s output leaked compose YAML:\n%s", out.String())
	}
	if strings.Contains(out.String(), "--cap-drop=") {
		t.Errorf("k8s output leaked docker-run flags:\n%s", out.String())
	}
}
