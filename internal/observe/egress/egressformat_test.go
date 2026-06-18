package egress

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

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
