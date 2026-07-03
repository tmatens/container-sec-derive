package format

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/observe/privileged"
	"github.com/tmatens/container-sec-derive/internal/obstest"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func privSidecar() *sidecar.Sidecar {
	s := sidecar.NewSidecar()
	s.Capabilities = []sidecar.Capability{{Name: "SYS_NICE"}}
	s.DeviceRecommendation = &sidecar.DeviceRecommendation{
		Devices:     []string{"/dev/dri/card0", "/dev/net/tun"},
		DerivedCaps: []string{"CAP_NET_ADMIN"},
	}
	return s
}

// TestPrivilegedDecompositionFlagsPartial asserts the v0.3 decomposition is
// marked partial and carries the security_opt caveat — the safety signal that
// keeps a JSON consumer from reading "drop privileged: true" as complete.
func TestPrivilegedDecompositionFlagsPartial(t *testing.T) {
	caps := obstest.WriteTemp(t, "caps.ndjson", obstest.PrivCapsFixture)
	dev := obstest.WriteTemp(t, "dev.ndjson", obstest.PrivDevFixture)
	s, err := privileged.ProducePrivilegedObservation(privileged.PrivilegedPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "gpu-1", InitWindowMs: 0},
		Fixture:       caps,
		DeviceFixture: dev,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pd := s.PrivilegedDecomposition
	if !pd.Partial {
		t.Error("decomposition must be marked partial at v0.3")
	}
	if pd.SecurityOpt != sidecar.PrivilegedSecurityOptCaveat {
		t.Errorf("security_opt = %q, want the caveat constant", pd.SecurityOpt)
	}
}

// TestPrivilegedTextFormattersWarn asserts every human-facing privileged
// formatter surfaces the partial-decomposition / security_opt caveat.
func TestPrivilegedTextFormattersWarn(t *testing.T) {
	const sentinel = "security_opt"
	formatters := map[string]func(io.Writer, *sidecar.Sidecar) error{
		"compose":    WritePrivilegedCompose,
		"docker-run": WritePrivilegedDockerRun,
		"k8s":        WritePrivilegedK8s,
		"oci":        WritePrivilegedOCI,
	}
	for name, fn := range formatters {
		var b strings.Builder
		if err := fn(&b, privSidecar()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(b.String(), sentinel) {
			t.Errorf("%s output omits the %q caveat:\n%s", name, sentinel, b.String())
		}
	}
}

func TestWritePrivilegedDockerRun(t *testing.T) {
	var b strings.Builder
	if err := WritePrivilegedDockerRun(&b, privSidecar()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"--cap-drop=ALL --cap-add=SYS_NICE", "--device /dev/dri/card0:/dev/dri/card0", "--device /dev/net/tun:/dev/net/tun"} {
		if !strings.Contains(out, want) {
			t.Errorf("docker-run missing %q\n%s", want, out)
		}
	}
}

func TestWritePrivilegedK8sSingleSecurityContext(t *testing.T) {
	var b strings.Builder
	if err := WritePrivilegedK8s(&b, privSidecar()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Count(out, "securityContext:") != 1 {
		t.Errorf("must emit exactly one securityContext:\n%s", out)
	}
	for _, want := range []string{"  privileged: false", "  capabilities:", "      - SYS_NICE", "#   - /dev/net/tun", "device-plugin"} {
		if !strings.Contains(out, want) {
			t.Errorf("k8s missing %q\n%s", want, out)
		}
	}
}

func TestWritePrivilegedOCIMergedJSON(t *testing.T) {
	var b strings.Builder
	if err := WritePrivilegedOCI(&b, privSidecar()); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Process struct {
			Capabilities struct {
				Bounding []string `json:"bounding"`
			} `json:"capabilities"`
		} `json:"process"`
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.Unmarshal([]byte(b.String()), &parsed); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, b.String())
	}
	if len(parsed.Process.Capabilities.Bounding) != 1 || parsed.Process.Capabilities.Bounding[0] != "CAP_SYS_NICE" {
		t.Errorf("bounding caps = %v, want [CAP_SYS_NICE]", parsed.Process.Capabilities.Bounding)
	}
	if parsed.Annotations["org.containersecderive.observed-devices"] != "/dev/dri/card0,/dev/net/tun" {
		t.Errorf("observed-devices annotation = %q", parsed.Annotations["org.containersecderive.observed-devices"])
	}
	if !strings.Contains(parsed.Annotations["org.containersecderive.privileged"], "not-required") {
		t.Errorf("privileged annotation missing: %v", parsed.Annotations)
	}
}

func TestWritePrivilegedComposePatchRemovesPrivileged(t *testing.T) {
	const in = "services:\n  gpu:\n    image: gpu:1\n    privileged: true\n"
	var b strings.Builder
	if err := WritePrivilegedComposePatch(&b, privSidecar(), []byte(in), "compose.yml", "gpu"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "-    privileged: true") {
		t.Errorf("must remove privileged: true\n%s", out)
	}
	for _, want := range []string{"+    cap_drop:", "+      - ALL", "+    cap_add:", "+      - SYS_NICE", "+    devices:", "+      - /dev/net/tun:/dev/net/tun"} {
		if !strings.Contains(out, want) {
			t.Errorf("compose-patch missing %q\n%s", want, out)
		}
	}
}

func TestWritePrivilegedComposeLintProfileContract(t *testing.T) {
	// Build a sidecar that clears the union contract.
	wl := t.TempDir() + "/w.sh"
	if err := os.WriteFile(wl, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := privSidecar()
	s.Image = "gpu"
	s.ImageDigest = "sha256:dead"
	s.DurationSeconds = 600
	s.Workload = wl
	s.ObservedAt = time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	s.Confidence.Level = sidecar.ConfidenceModerate

	var b strings.Builder
	if err := WritePrivilegedComposeLintProfile(&b, s, false); err != nil {
		t.Fatalf("contract should pass: %v", err)
	}
	out := b.String()
	for _, want := range []string{"observer: privileged", "  privileged_decomposition:\n", "partial: true", "security_opt_unobserved: true", "cap_add: [SYS_NICE]", "devices: [/dev/dri/card0, /dev/net/tun]"} {
		if !strings.Contains(out, want) {
			t.Errorf("profile missing %q\n%s", want, out)
		}
	}

	// Device-replica disagreement must fail the union contract.
	s.Target.ReplicaDeviceDisagreement = []string{"/dev/net/tun"}
	if v := CheckPrivilegedComposeLintContract(s); len(v) == 0 {
		t.Error("device-replica disagreement should violate the union contract")
	}
}
