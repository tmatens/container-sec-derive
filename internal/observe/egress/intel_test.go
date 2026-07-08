package egress

import (
	"reflect"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestIsInternalName(t *testing.T) {
	internal := []string{
		"", "localhost", "db", // empty + dotless single-label
		"db.internal", "svc.lan", "host.local", "x.home", "y.corp",
		"z.intranet", "1.0.0.10.in-addr.arpa", "foo.test", "bar.example", "baz.invalid",
		"DB.INTERNAL", "svc.lan.", // case + trailing dot
	}
	for _, n := range internal {
		if !isInternalName(n) {
			t.Errorf("isInternalName(%q) = false, want true", n)
		}
	}
	public := []string{"api.example.com", "cdn.example.org", "github.com", "s3.amazonaws.com"}
	for _, n := range public {
		if isInternalName(n) {
			t.Errorf("isInternalName(%q) = true, want false", n)
		}
	}
}

func TestIsPrivateOrReservedIP(t *testing.T) {
	private := []string{
		"10.0.0.5", "172.16.3.4", "192.168.1.1", // RFC-1918
		"100.64.0.1", "100.127.255.254", // CGNAT /10
		"127.0.0.1", "::1", // loopback
		"169.254.1.1", "fe80::1", // link-local
		"fd00::5",              // ULA
		"0.0.0.0", "224.0.0.1", // unspecified + multicast
		"not-an-ip", // unparseable -> conservative true
	}
	for _, ip := range private {
		if !isPrivateOrReservedIP(ip) {
			t.Errorf("isPrivateOrReservedIP(%q) = false, want true", ip)
		}
	}
	public := []string{"1.1.1.1", "8.8.8.8", "104.18.24.232", "2606:4700:4700::1111", "100.128.0.1"}
	for _, ip := range public {
		if isPrivateOrReservedIP(ip) {
			t.Errorf("isPrivateOrReservedIP(%q) = true, want false", ip)
		}
	}
}

func TestDestVisibility(t *testing.T) {
	cases := []struct {
		name  string
		addrs []string
		want  string
	}{
		{"api.example.com", []string{"1.1.1.1"}, sidecar.EgressVisibilityImageIntrinsic},
		{"db.internal", []string{"10.0.0.5"}, sidecar.EgressVisibilityDeploymentSpecific},     // internal name
		{"svc.example.com", []string{"10.0.0.9"}, sidecar.EgressVisibilityDeploymentSpecific}, // public name, private IP (split-horizon)
		{"", []string{"8.8.8.8"}, sidecar.EgressVisibilityImageIntrinsic},                     // public IP-only
		{"", []string{"192.168.1.2"}, sidecar.EgressVisibilityDeploymentSpecific},             // private IP-only
		{"api.example.com", nil, sidecar.EgressVisibilityDeploymentSpecific},                  // no addrs -> conservative
	}
	for _, c := range cases {
		if got := destVisibility(c.name, c.addrs); got != c.want {
			t.Errorf("destVisibility(%q, %v) = %q, want %q", c.name, c.addrs, got, c.want)
		}
	}
}

// TestBuildEgressIntel_NameLevelProvenance is the core #206 assertion: provenance
// is computed at NAME granularity — a name is confirmed if ANY of its resolved
// addresses was dialed (so a multi-address CDN/dual-stack pool where one address
// connected is confirmed, not a false gap), and resolved_only only when NONE was.
func TestBuildEgressIntel_NameLevelProvenance(t *testing.T) {
	dests := []sidecar.EgressDest{
		{Addr: "1.1.1.1", Port: 443, Version: 4},    // one address of api.example.com
		{Addr: "10.0.0.5", Port: 5432, Version: 4},  // db.internal (has a name)
		{Addr: "203.0.113.9", Port: 80, Version: 4}, // IP-only (no DNS)
	}
	corr := &dnsCorrelation{HostnamesByIP: map[string][]string{
		// api.example.com resolved to two IPs; only 1.1.1.1 was dialed -> confirmed
		"1.1.1.1":              {"api.example.com"},
		"1.0.0.1":              {"api.example.com"},
		"2606:4700:4700::1111": {"api.example.com"},
		// cdn.example.com resolved but never dialed -> resolved_only
		"104.18.24.232": {"cdn.example.com"},
		// db.internal dialed -> confirmed, deployment_specific
		"10.0.0.5": {"db.internal"},
	}}

	got := buildEgressIntel(dests, corr)
	want := []sidecar.EgressDestinationIntel{
		{Name: "api.example.com", Addrs: []string{"1.0.0.1", "1.1.1.1", "2606:4700:4700::1111"}, Ports: []int{443}, Provenance: sidecar.EgressProvenanceConfirmed, Visibility: sidecar.EgressVisibilityImageIntrinsic},
		{Name: "cdn.example.com", Addrs: []string{"104.18.24.232"}, Provenance: sidecar.EgressProvenanceResolvedOnly, Visibility: sidecar.EgressVisibilityImageIntrinsic},
		{Name: "db.internal", Addrs: []string{"10.0.0.5"}, Ports: []int{5432}, Provenance: sidecar.EgressProvenanceConfirmed, Visibility: sidecar.EgressVisibilityDeploymentSpecific},
		{Addrs: []string{"203.0.113.9"}, Ports: []int{80}, Provenance: sidecar.EgressProvenanceConfirmed, Visibility: sidecar.EgressVisibilityImageIntrinsic},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildEgressIntel mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestBuildEgressIntel_TCPOnlyAndEmpty(t *testing.T) {
	// No DNS correlation: every connected IP is an IP-only entry, classified by IP.
	got := buildEgressIntel([]sidecar.EgressDest{
		{Addr: "8.8.8.8", Port: 443, Version: 4},
		{Addr: "192.168.1.2", Port: 22, Version: 4},
	}, nil)
	want := []sidecar.EgressDestinationIntel{
		{Addrs: []string{"192.168.1.2"}, Ports: []int{22}, Provenance: sidecar.EgressProvenanceConfirmed, Visibility: sidecar.EgressVisibilityDeploymentSpecific},
		{Addrs: []string{"8.8.8.8"}, Ports: []int{443}, Provenance: sidecar.EgressProvenanceConfirmed, Visibility: sidecar.EgressVisibilityImageIntrinsic},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TCP-only mismatch:\n got %+v\nwant %+v", got, want)
	}
	if buildEgressIntel(nil, nil) != nil {
		t.Errorf("buildEgressIntel(nil, nil) = non-nil, want nil (omitempty-absent)")
	}
}
