package format

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/observe/capadd"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// capaddGranted is the validate-set the fixture-driven formatter tests use: a
// granted set exercising every branch — a finer substitution (SYS_ADMIN ->
// PERFMON), a no-finer used cap (NET_RAW, SYS_PTRACE), and an unused/removable
// cap (SYS_MODULE, never observed).
const capaddGranted = "SYS_ADMIN,NET_RAW,SYS_MODULE,SYS_PTRACE"

// capaddSidecarFromFixture builds a capadd sidecar from the reference fixture
// through the exported pipeline producer. The capadd package's own white-box
// tests build it from internals; the formatter tests here only need the public
// surface.
func capaddSidecarFromFixture(t *testing.T, granted string, hasGranted bool) *sidecar.Sidecar {
	t.Helper()
	active := capadd.ParseCapSet(granted)
	if active == nil {
		active = capadd.DangerousCaps
	}
	s, err := capadd.ProduceCapaddObservation(capadd.CapaddPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "aabbccddeeff0011"},
		ActiveSet:     active,
		Granted:       hasGranted,
		Fixture:       "../../testdata/capadd/sample.ndjson",
	}, nil)
	if err != nil {
		t.Fatalf("ProduceCapaddObservation: %v", err)
	}
	return s
}

// TestCapaddCompose_GrantedEmitsCapAdd checks the compose formatter emits the
// advisory comments plus a minimized cap_add when a granted set was supplied, and
// the advisory alone otherwise.
func TestCapaddCompose(t *testing.T) {
	s := capaddSidecarFromFixture(t, capaddGranted, true)
	var buf bytes.Buffer
	if err := WriteCapaddCompose(&buf, s.CapaddValidation); err != nil {
		t.Fatalf("WriteCapaddCompose: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# csd dangerous cap_add validation",
		"# SYS_ADMIN: observed only via perf_event_open; PERFMON likely suffices",
		"# dropped (unused under this workload): SYS_MODULE",
		"cap_add:",
		"  - PERFMON",
		"  - SYS_PTRACE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compose output missing %q:\n%s", want, out)
		}
	}

	// Default mode: advisory only, no cap_add block.
	s = capaddSidecarFromFixture(t, "", false)
	buf.Reset()
	if err := WriteCapaddCompose(&buf, s.CapaddValidation); err != nil {
		t.Fatalf("WriteCapaddCompose default: %v", err)
	}
	if strings.Contains(buf.String(), "cap_add:") {
		t.Errorf("default mode should not emit cap_add block:\n%s", buf.String())
	}
}

// TestCapaddFormatters_Smoke exercises the remaining text formatters for basic
// validity (no error, key content present) in granted mode.
func TestCapaddFormatters_Smoke(t *testing.T) {
	s := capaddSidecarFromFixture(t, capaddGranted, true)
	val := s.CapaddValidation

	var buf bytes.Buffer
	if err := WriteCapaddDockerRun(&buf, val); err != nil {
		t.Fatalf("docker-run: %v", err)
	}
	if !strings.Contains(buf.String(), "--cap-add PERFMON") {
		t.Errorf("docker-run missing --cap-add PERFMON:\n%s", buf.String())
	}

	buf.Reset()
	if err := WriteCapaddK8s(&buf, val); err != nil {
		t.Fatalf("k8s: %v", err)
	}
	if !strings.Contains(buf.String(), "drop: [ALL]") || !strings.Contains(buf.String(), "PERFMON") {
		t.Errorf("k8s output unexpected:\n%s", buf.String())
	}

	buf.Reset()
	if err := WriteCapaddOCI(&buf, val); err != nil {
		t.Fatalf("oci: %v", err)
	}
	var oci struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal(buf.Bytes(), &oci); err != nil {
		t.Fatalf("oci not valid JSON: %v\n%s", err, buf.String())
	}
	if oci.Annotations["org.containersecderive.recommended-cap-add"] != "NET_RAW,PERFMON,SYS_PTRACE" {
		t.Errorf("oci recommended-cap-add = %q", oci.Annotations["org.containersecderive.recommended-cap-add"])
	}
}

// TestCapaddComposePatch rewrites a service's cap_add to the recommended set.
func TestCapaddComposePatch(t *testing.T) {
	s := capaddSidecarFromFixture(t, capaddGranted, true)
	compose := []byte("services:\n  app:\n    image: myapp:1\n    cap_add:\n      - SYS_ADMIN\n      - NET_RAW\n      - SYS_MODULE\n      - SYS_PTRACE\n")
	var buf bytes.Buffer
	if err := WriteCapaddComposePatch(&buf, s.CapaddValidation, compose, "compose.yml", "app"); err != nil {
		t.Fatalf("compose-patch: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "-      - SYS_ADMIN") && !strings.Contains(out, "-      - SYS_MODULE") {
		t.Errorf("patch should remove SYS_ADMIN/SYS_MODULE lines:\n%s", out)
	}
	if !strings.Contains(out, "+      - PERFMON") {
		t.Errorf("patch should add PERFMON:\n%s", out)
	}

	// Default mode proposes no change.
	s = capaddSidecarFromFixture(t, "", false)
	buf.Reset()
	if err := WriteCapaddComposePatch(&buf, s.CapaddValidation, compose, "compose.yml", "app"); err != nil {
		t.Fatalf("compose-patch default: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("default mode should propose no patch, got:\n%s", buf.String())
	}
}

// TestCapaddProfile_ContractGate checks the compose-lint-profile contract:
// without a granted set it is a violation (no minimized cap_add to contribute),
// and --allow-exploratory emits under exploratory:.
func TestCapaddProfile_ContractGate(t *testing.T) {
	s := capaddSidecarFromFixture(t, "", false)
	var buf bytes.Buffer
	err := WriteCapaddComposeLintProfile(&buf, s, false)
	if err == nil {
		t.Fatal("expected contract violation without a granted set")
	}
	if !strings.Contains(err.Error(), "granted set not provided") {
		t.Errorf("violation = %v, want granted-set mention", err)
	}

	// allow-exploratory emits anyway, with status: exploratory.
	buf.Reset()
	if err := WriteCapaddComposeLintProfile(&buf, s, true); err != nil {
		t.Fatalf("exploratory emit: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "status: exploratory") {
		t.Errorf("exploratory output missing status: exploratory:\n%s", out)
	}
	if !strings.Contains(out, "  cap_add_validation:\n") {
		t.Errorf("exploratory output missing cap_add_validation dimension:\n%s", out)
	}
}
