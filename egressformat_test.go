package main

import (
	"bytes"
	"strings"
	"testing"
)

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
		if exitCodeFor(err) != ExitUsage {
			t.Errorf("caps --format %s: exit = %d, want ExitUsage (%d)", f, exitCodeFor(err), ExitUsage)
		}
	}
}

func TestWriteEgress_EmptyAndIPv6(t *testing.T) {
	// Empty allowlist → deny-all, with the warning comment in both formats.
	empty := NewSidecar()
	empty.EgressRecommendation = &egressRecommendation{Allowlist: nil, Caveat: EgressCaveat}
	var nft bytes.Buffer
	if err := writeEgressNftables(&nft, empty); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nft.String(), "policy drop;") || !strings.Contains(nft.String(), "denies ALL egress") {
		t.Errorf("empty nftables should be deny-all:\n%s", nft.String())
	}

	// IPv6 destination → ip6 daddr / /128.
	v6 := NewSidecar()
	v6.Image = "svc:2"
	v6.EgressRecommendation = &egressRecommendation{
		Allowlist: []egressDest{{Addr: "2606:4700:4700::1111", Port: 853, Version: 6}},
		Caveat:    EgressCaveat,
	}
	var n6, k6 bytes.Buffer
	if err := writeEgressNftables(&n6, v6); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(n6.String(), "ip6 daddr 2606:4700:4700::1111 tcp dport 853 accept") {
		t.Errorf("ipv6 nftables wrong:\n%s", n6.String())
	}
	if err := writeEgressNetworkPolicy(&k6, v6); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(k6.String(), "cidr: 2606:4700:4700::1111/128") {
		t.Errorf("ipv6 networkpolicy should use /128:\n%s", k6.String())
	}
}

func TestEgressPolicyName(t *testing.T) {
	cases := []struct {
		image, selector, want string
	}{
		{"ghcr.io/acme/My_App:1.2", "", "my-app-egress"},
		{"", "web-1", "web-1-egress"},
		{"", "", "app-egress"},
		{"postgres:16", "", "postgres-egress"},
	}
	for _, c := range cases {
		s := NewSidecar()
		s.Image = c.image
		s.Target.Selector = c.selector
		if got := egressPolicyName(s); got != c.want {
			t.Errorf("egressPolicyName(image=%q sel=%q) = %q, want %q", c.image, c.selector, got, c.want)
		}
	}
}
