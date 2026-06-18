package egress

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestWriteEgress_DNSEnriched(t *testing.T) {
	// A sidecar with a resolver and a hostname-annotated destination (#159):
	// both formatters must emit the UDP resolver allow rule and label the IP
	// rule with its hostname.
	s := sidecar.NewSidecar()
	s.Image = "svc:1"
	s.EgressDestinations = []sidecar.EgressDestination{
		{Addr: "1.1.1.1", Port: 443, Version: 4, Hostnames: []string{"api.example.com"}},
	}
	s.EgressRecommendation = &sidecar.EgressRecommendation{
		Allowlist: []sidecar.EgressDest{{Addr: "1.1.1.1", Port: 443, Version: 4}},
		Resolvers: []sidecar.EgressDest{{Addr: "10.0.0.2", Port: 53, Version: 4}},
		Caveat:    EgressCaveat,
	}

	var nft bytes.Buffer
	if err := WriteEgressNftables(&nft, s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nft.String(), "ip daddr 10.0.0.2 udp dport 53 accept # DNS resolver") {
		t.Errorf("nftables missing UDP resolver rule:\n%s", nft.String())
	}
	if !strings.Contains(nft.String(), "ip daddr 1.1.1.1 tcp dport 443 accept # api.example.com") {
		t.Errorf("nftables missing hostname-commented dest rule:\n%s", nft.String())
	}
	// The resolver UDP rule must precede the TCP dest rule (DNS first).
	if i, j := strings.Index(nft.String(), "udp dport 53"), strings.Index(nft.String(), "tcp dport 443"); i < 0 || j < 0 || i > j {
		t.Errorf("resolver rule should precede dest rule:\n%s", nft.String())
	}

	var k8s bytes.Buffer
	if err := WriteEgressNetworkPolicy(&k8s, s); err != nil {
		t.Fatal(err)
	}
	out := k8s.String()
	if !strings.Contains(out, "protocol: UDP") || !strings.Contains(out, "port: 53") {
		t.Errorf("NetworkPolicy missing UDP/53 resolver rule:\n%s", out)
	}
	if !strings.Contains(out, "cidr: 10.0.0.2/32") {
		t.Errorf("NetworkPolicy missing resolver cidr:\n%s", out)
	}
	if !strings.Contains(out, "# api.example.com") {
		t.Errorf("NetworkPolicy missing hostname annotation:\n%s", out)
	}
}

func TestWriteEgress_ResolverOnlyNoTCPDests(t *testing.T) {
	// DNS observed but no TCP connects: the policy must still allow the resolver
	// (not collapse to deny-all), or the workload's only egress — DNS — breaks.
	s := sidecar.NewSidecar()
	s.EgressRecommendation = &sidecar.EgressRecommendation{
		Allowlist: nil,
		Resolvers: []sidecar.EgressDest{{Addr: "10.0.0.2", Port: 53, Version: 4}},
		Caveat:    EgressCaveat,
	}
	var k8s bytes.Buffer
	if err := WriteEgressNetworkPolicy(&k8s, s); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(k8s.String(), "egress: []") {
		t.Errorf("resolver-only policy must not be deny-all:\n%s", k8s.String())
	}
	if !strings.Contains(k8s.String(), "protocol: UDP") {
		t.Errorf("resolver-only policy missing UDP rule:\n%s", k8s.String())
	}
}

func TestWriteEgress_EmptyAndIPv6(t *testing.T) {
	// Empty allowlist → deny-all, with the warning comment in both formats.
	empty := sidecar.NewSidecar()
	empty.EgressRecommendation = &sidecar.EgressRecommendation{Allowlist: nil, Caveat: EgressCaveat}
	var nft bytes.Buffer
	if err := WriteEgressNftables(&nft, empty); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nft.String(), "policy drop;") || !strings.Contains(nft.String(), "denies ALL egress") {
		t.Errorf("empty nftables should be deny-all:\n%s", nft.String())
	}

	// IPv6 destination → ip6 daddr / /128.
	v6 := sidecar.NewSidecar()
	v6.Image = "svc:2"
	v6.EgressRecommendation = &sidecar.EgressRecommendation{
		Allowlist: []sidecar.EgressDest{{Addr: "2606:4700:4700::1111", Port: 853, Version: 6}},
		Caveat:    EgressCaveat,
	}
	var n6, k6 bytes.Buffer
	if err := WriteEgressNftables(&n6, v6); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(n6.String(), "ip6 daddr 2606:4700:4700::1111 tcp dport 853 accept") {
		t.Errorf("ipv6 nftables wrong:\n%s", n6.String())
	}
	if err := WriteEgressNetworkPolicy(&k6, v6); err != nil {
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
		s := sidecar.NewSidecar()
		s.Image = c.image
		s.Target.Selector = c.selector
		if got := egressPolicyName(s); got != c.want {
			t.Errorf("egressPolicyName(image=%q sel=%q) = %q, want %q", c.image, c.selector, got, c.want)
		}
	}
}
