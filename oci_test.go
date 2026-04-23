package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteOCI_StandardCapSet(t *testing.T) {
	s := NewSidecar()
	s.Capabilities = []Capability{
		{Name: "CHOWN"},
		{Name: "DAC_OVERRIDE"},
		{Name: "SETUID"},
	}
	var buf bytes.Buffer
	if err := writeOCI(&buf, s); err != nil {
		t.Fatalf("writeOCI: %v", err)
	}
	want := `{
  "process": {
    "capabilities": {
      "bounding": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_SETUID"
      ],
      "effective": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_SETUID"
      ],
      "permitted": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_SETUID"
      ],
      "inheritable": [],
      "ambient": []
    }
  }
}
`
	if buf.String() != want {
		t.Errorf("oci output mismatch:\ngot:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestWriteOCI_EmptyCapSetKeepsEmptyArrays(t *testing.T) {
	// Empty observed set produces three empty populated-set arrays plus
	// the always-empty inheritable/ambient. The "drop everything, add
	// nothing" analog for OCI is three empty arrays, not omission --
	// downstream merge tools (jq, umoci) rely on explicit [] to clear
	// any pre-existing caps in the target config.json.
	s := NewSidecar()
	var buf bytes.Buffer
	if err := writeOCI(&buf, s); err != nil {
		t.Fatalf("writeOCI: %v", err)
	}
	want := `{
  "process": {
    "capabilities": {
      "bounding": [],
      "effective": [],
      "permitted": [],
      "inheritable": [],
      "ambient": []
    }
  }
}
`
	if buf.String() != want {
		t.Errorf("empty cap set output mismatch:\ngot:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestWriteOCI_PreservesAggregatorOrder(t *testing.T) {
	// The aggregator sorts caps ascending; the formatter must not reorder
	// them. A non-sorted input here would still round-trip through JSON
	// encoding in insertion order because the encoder writes slices in
	// index order, but the sorted-input case is what production hits.
	s := NewSidecar()
	s.Capabilities = []Capability{
		{Name: "A"}, {Name: "B"}, {Name: "C"},
	}
	var buf bytes.Buffer
	if err := writeOCI(&buf, s); err != nil {
		t.Fatalf("writeOCI: %v", err)
	}
	var got struct {
		Process struct {
			Capabilities struct {
				Bounding []string `json:"bounding"`
			} `json:"capabilities"`
		} `json:"process"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"CAP_A", "CAP_B", "CAP_C"}
	if len(got.Process.Capabilities.Bounding) != len(want) {
		t.Fatalf("bounding len = %d, want %d", len(got.Process.Capabilities.Bounding), len(want))
	}
	for i, w := range want {
		if got.Process.Capabilities.Bounding[i] != w {
			t.Errorf("bounding[%d] = %q, want %q", i, got.Process.Capabilities.Bounding[i], w)
		}
	}
}

func TestRun_OCIFormatEndToEnd(t *testing.T) {
	// End-to-end: --format oci must route through run()'s dispatch and
	// produce the process.capabilities JSON on stdout. Guards against a
	// main.go wiring regression where the switch silently falls back
	// to compose, docker-run, or k8s.
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson",
		"--container", "postgres-1",
		"--format", "oci",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	// Must be valid JSON with the expected top-level shape.
	var snippet struct {
		Process struct {
			Capabilities struct {
				Bounding    []string `json:"bounding"`
				Effective   []string `json:"effective"`
				Permitted   []string `json:"permitted"`
				Inheritable []string `json:"inheritable"`
				Ambient     []string `json:"ambient"`
			} `json:"capabilities"`
		} `json:"process"`
	}
	if err := json.Unmarshal(out.Bytes(), &snippet); err != nil {
		t.Fatalf("stdout not valid oci JSON: %v\noutput:\n%s", err, out.String())
	}
	if snippet.Process.Capabilities.Inheritable == nil {
		t.Error("inheritable should be explicit empty array, not null")
	}
	if snippet.Process.Capabilities.Ambient == nil {
		t.Error("ambient should be explicit empty array, not null")
	}
	// Every populated cap should be CAP_-prefixed. Cheapest guard against
	// a regression to bare names.
	for _, c := range snippet.Process.Capabilities.Bounding {
		if !strings.HasPrefix(c, "CAP_") {
			t.Errorf("bounding entry %q missing CAP_ prefix", c)
		}
	}
	// Must not contain compose / docker-run / k8s markers -- cheapest
	// guard against dispatch falling through to another formatter.
	if strings.HasPrefix(out.String(), "cap_drop:") {
		t.Errorf("oci output leaked compose YAML:\n%s", out.String())
	}
	if strings.Contains(out.String(), "--cap-drop=") {
		t.Errorf("oci output leaked docker-run flags:\n%s", out.String())
	}
	if strings.HasPrefix(out.String(), "securityContext:") {
		t.Errorf("oci output leaked k8s YAML:\n%s", out.String())
	}
}
