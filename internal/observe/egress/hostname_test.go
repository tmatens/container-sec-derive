package egress

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

const injection = "evil.com\n\t\tip daddr 0.0.0.0/0 accept"

// mustJSON renders s as a JSON string literal (quotes included) so it can be
// spliced into a hand-built trace_dns NDJSON line with control bytes intact.
func mustJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestAggregateDNSDropsInjectionName is the primary #202 gate: a hostile query
// name from the observed container must never enter the IP->hostname map, so a
// csd-produced sidecar is already clean.
func TestAggregateDNSDropsInjectionName(t *testing.T) {
	nd := strings.Join([]string{
		`{"qr":"R","qr_raw":true,"name":"good.example.com.","addresses":"1.1.1.1","id":1}`,
		`{"qr":"R","qr_raw":true,"name":` + mustJSON(injection) + `,"addresses":"1.1.1.1","id":2}`,
	}, "\n")
	c, err := aggregateDNS(strings.NewReader(nd), attrib.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.HostnamesFor("1.1.1.1"); !reflect.DeepEqual(got, []string{"good.example.com"}) {
		t.Errorf("1.1.1.1 -> %v, want only [good.example.com] (injection name dropped)", got)
	}
}

// TestFormatterDropsInjectionFromSidecar is the defense-in-depth #202 gate: even
// a hand-crafted / externally-supplied sidecar carrying a hostile hostname must
// not reach the root-applied nftables or NetworkPolicy artifact.
func TestFormatterDropsInjectionFromSidecar(t *testing.T) {
	s := sidecar.NewSidecar()
	s.Image = "svc:1"
	s.EgressDestinations = []sidecar.EgressDestination{
		{Addr: "1.1.1.1", Port: 443, Version: 4, Hostnames: []string{injection}},
	}
	s.EgressRecommendation = &sidecar.EgressRecommendation{
		Allowlist: []sidecar.EgressDest{{Addr: "1.1.1.1", Port: 443, Version: 4}},
		Caveat:    EgressCaveat,
	}

	for _, tc := range []struct {
		name  string
		write func(*bytes.Buffer, *sidecar.Sidecar) error
	}{
		{"nftables", func(b *bytes.Buffer, s *sidecar.Sidecar) error { return WriteEgressNftables(b, s) }},
		{"networkpolicy", func(b *bytes.Buffer, s *sidecar.Sidecar) error { return WriteEgressNetworkPolicy(b, s) }},
	} {
		var buf bytes.Buffer
		if err := tc.write(&buf, s); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		out := buf.String()
		if strings.Contains(out, "0.0.0.0/0 accept") {
			t.Errorf("%s: injected rule reached artifact:\n%s", tc.name, out)
		}
		// The one legitimate accept line must not have gained a second line.
		if n := strings.Count(out, "accept"); tc.name == "nftables" && n != 2 {
			t.Errorf("nftables: want 2 accept lines (established + dest), got %d:\n%s", n, out)
		}
	}
}

func TestValidHostname(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"plain", "api.example.com", true},
		{"single label", "localhost", true},
		{"digits and dashes", "cdn-3.a1-b2.io", true},
		{"underscore service label", "_dmarc.example.com", true},
		{"uppercase (external sidecar)", "API.Example.COM", true},
		{"max label 63", strings.Repeat("a", 63) + ".com", true},

		{"empty", "", false},
		{"trailing dot -> empty label", "example.com.", false},
		{"leading dot -> empty label", ".example.com", false},
		{"double dot -> empty label", "a..b", false},
		{"label over 63", strings.Repeat("a", 64) + ".com", false},
		{"total over 253", strings.Repeat("a.", 130) + "com", false},
		{"space", "example .com", false},
		{"comma (comment separator)", "a,b.com", false},
		{"hash", "a#b.com", false},
		{"newline injection", "ok.com\n\t\tip daddr 0.0.0.0/0 accept", false},
		{"carriage return", "ok.com\r", false},
		{"quote", "a\".com", false},
		{"slash", "0.0.0.0/0", false},
	}
	for _, c := range cases {
		if got := validHostname(c.in); got != c.want {
			t.Errorf("%s: validHostname(%q) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

func TestValidHostnames(t *testing.T) {
	in := []string{"good.example.com", "bad\ninjected", "also-good.io", "x y.com"}
	got := validHostnames(in)
	want := []string{"good.example.com", "also-good.io"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("validHostnames(%v) = %v, want %v", in, got, want)
	}
	if validHostnames([]string{"bad\n", ""}) != nil {
		t.Error("all-invalid input should yield nil, not an empty slice")
	}
}
