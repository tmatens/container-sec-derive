package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

const egressFixture = "testdata/ig-versions/v0.51.0/trace_tcp_sample.ndjson"

func runEgressFormat(t *testing.T, format string) string {
	t.Helper()
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--observe", "egress", "--container", "egress-target",
		"--fixture", egressFixture, "--format", format,
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run egress --format %s: %v (stderr=%s)", format, err, errBuf.String())
	}
	return out.String()
}

func TestRunEgress_Nftables(t *testing.T) {
	got := runEgressFormat(t, "nftables")
	for _, want := range []string{
		"table inet csd_egress {",
		"type filter hook output priority 0; policy drop;",
		"ct state established,related accept",
		"ip daddr 1.1.1.1 tcp dport 443 accept",
		"ip daddr 10.0.0.5 tcp dport 5432 accept",
		"WARNING:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("nftables output missing %q\n---\n%s", want, got)
		}
	}
}

func TestRunEgress_NetworkPolicy(t *testing.T) {
	got := runEgressFormat(t, "k8s-networkpolicy")
	for _, want := range []string{
		"kind: NetworkPolicy",
		"name: myapp-egress",
		"- Egress",
		"cidr: 1.1.1.1/32",
		"port: 443",
		"cidr: 10.0.0.5/32",
		"port: 5432",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("networkpolicy output missing %q\n---\n%s", want, got)
		}
	}
}

func TestEgressFormat_GuardNonEgress(t *testing.T) {
	for _, f := range []string{"nftables", "k8s-networkpolicy"} {
		var out, errBuf bytes.Buffer
		err := run([]string{
			"--observe", "caps", "--container", "x",
			"--fixture", "testdata/ig-versions/v0.51.0/sample.ndjson", "--format", f,
		}, &out, &errBuf)
		if exit.CodeFor(err) != exit.Usage {
			t.Errorf("caps --format %s: exit = %d, want exit.Usage (%d)", f, exit.CodeFor(err), exit.Usage)
		}
	}
}

func TestRunEgress_FormatGuard(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--observe", "egress", "--container", "egress-target",
		"--fixture", egressFixture, "--format", "json",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("egress --format json: %v", err)
	}
	var s sidecar.Sidecar
	if jerr := json.Unmarshal(out.Bytes(), &s); jerr != nil {
		t.Fatalf("stdout is not valid sidecar JSON: %v", jerr)
	}
	if s.EgressRecommendation == nil || len(s.EgressRecommendation.Allowlist) != 2 {
		t.Errorf("run() egress allowlist = %+v, want 2", s.EgressRecommendation)
	}

	var o2, e2 bytes.Buffer
	err = run([]string{
		"--observe", "egress", "--container", "egress-target",
		"--fixture", egressFixture, "--format", "compose",
	}, &o2, &e2)
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("egress --format compose: exit = %d, want exit.Usage (%d)", exit.CodeFor(err), exit.Usage)
	}
}
