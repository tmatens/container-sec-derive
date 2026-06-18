package egress

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
)

func TestAggregateDNSCorrelation(t *testing.T) {
	// Two response packets map two IPs to two hostnames; both queries and
	// responses share one resolver (10.0.0.2:53). All for one container.
	nd := strings.Join([]string{
		`{"qr":"Q","qr_raw":false,"name":"api.example.com.","id":1,"dst":{"addr":"10.0.0.2","port":53,"version":4},"runtime":{"containerName":"web"}}`,
		`{"qr":"R","qr_raw":true,"name":"api.example.com.","addresses":"1.1.1.1","id":1,"src":{"addr":"10.0.0.2","port":53,"version":4},"runtime":{"containerName":"web"}}`,
		`{"qr":"R","qr_raw":true,"name":"db.internal.","addresses":"10.0.0.5","id":2,"src":{"addr":"10.0.0.2","port":53,"version":4},"runtime":{"containerName":"web"}}`,
	}, "\n")
	c, err := aggregateDNS(strings.NewReader(nd), attrib.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.HostnamesFor("1.1.1.1"); !reflect.DeepEqual(got, []string{"api.example.com"}) {
		t.Errorf("1.1.1.1 -> %v, want [api.example.com]", got)
	}
	if got := c.HostnamesFor("10.0.0.5"); !reflect.DeepEqual(got, []string{"db.internal"}) {
		t.Errorf("10.0.0.5 -> %v, want [db.internal]", got)
	}
	if len(c.Resolvers) != 1 || c.Resolvers[0].Addr != "10.0.0.2" || c.Resolvers[0].Port != 53 {
		t.Errorf("Resolvers = %+v, want one 10.0.0.2:53", c.Resolvers)
	}
	if c.EventCount != 3 {
		t.Errorf("EventCount = %d, want 3", c.EventCount)
	}
}

func TestAggregateDNSMultipleHostnamesOneIP(t *testing.T) {
	// Two names resolving to the same IP (shared CDN) must both annotate it,
	// sorted and de-duplicated.
	nd := strings.Join([]string{
		`{"qr":"R","qr_raw":true,"name":"b.example.com.","addresses":"1.1.1.1","id":1}`,
		`{"qr":"R","qr_raw":true,"name":"a.example.com.","addresses":"1.1.1.1","id":2}`,
		`{"qr":"R","qr_raw":true,"name":"a.example.com.","addresses":"1.1.1.1","id":3}`,
	}, "\n")
	c, err := aggregateDNS(strings.NewReader(nd), attrib.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.HostnamesFor("1.1.1.1"); !reflect.DeepEqual(got, []string{"a.example.com", "b.example.com"}) {
		t.Errorf("1.1.1.1 -> %v, want [a.example.com b.example.com]", got)
	}
}

func TestAggregateDNSSelectorFilters(t *testing.T) {
	// Two containers; the selector keeps only the matching one's mappings and
	// resolver. The "other" container uses a different resolver (10.9.9.9).
	nd := strings.Join([]string{
		`{"qr":"R","qr_raw":true,"name":"keep.example.com.","addresses":"1.1.1.1","id":1,"src":{"addr":"10.0.0.2","port":53},"runtime":{"containerName":"web"}}`,
		`{"qr":"R","qr_raw":true,"name":"drop.example.org.","addresses":"203.0.113.7","id":2,"src":{"addr":"10.9.9.9","port":53},"runtime":{"containerName":"other"}}`,
	}, "\n")
	c, err := aggregateDNS(strings.NewReader(nd), attrib.Opts{Container: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if c.HostnamesFor("203.0.113.7") != nil {
		t.Errorf("other container's mapping leaked: %v", c.HostnamesByIP)
	}
	if got := c.HostnamesFor("1.1.1.1"); !reflect.DeepEqual(got, []string{"keep.example.com"}) {
		t.Errorf("1.1.1.1 -> %v, want [keep.example.com]", got)
	}
	if len(c.Resolvers) != 1 || c.Resolvers[0].Addr != "10.0.0.2" {
		t.Errorf("Resolvers = %+v, want only the matched container's 10.0.0.2", c.Resolvers)
	}
	if c.EventCount != 1 {
		t.Errorf("EventCount = %d, want 1 (only the matched container)", c.EventCount)
	}
}

func TestAggregateDNSNXDomainNoMapping(t *testing.T) {
	// An NXDomain response carries no addresses → no IP mapping, but the
	// resolver is still recorded (the query traffic happened).
	nd := `{"qr":"R","qr_raw":true,"name":"missing.example.com.","rcode":"NXDomain","addresses":"","id":1,"src":{"addr":"10.0.0.2","port":53}}`
	c, err := aggregateDNS(strings.NewReader(nd), attrib.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.HostnamesByIP) != 0 {
		t.Errorf("HostnamesByIP = %v, want empty for NXDomain", c.HostnamesByIP)
	}
	if len(c.Resolvers) != 1 {
		t.Errorf("Resolvers = %+v, want the resolver still recorded", c.Resolvers)
	}
}

func TestAggregateDNSMalformedLineErrors(t *testing.T) {
	if _, err := aggregateDNS(strings.NewReader("{not json}"), attrib.Opts{}); err == nil {
		t.Errorf("expected a hard error on a malformed line")
	}
}

func TestAggregateDNSNilCorrelationSafe(t *testing.T) {
	var c *dnsCorrelation
	if got := c.HostnamesFor("1.1.1.1"); got != nil {
		t.Errorf("nil correlation HostnamesFor = %v, want nil", got)
	}
}

// TestAggregateDNSOnSampleFixture exercises the committed fixture end-to-end:
// the egress-target container's responses must map the same IPs trace_tcp's
// sample recorded (1.1.1.1, 10.0.0.5), and the resolver must be present.
func TestAggregateDNSOnSampleFixture(t *testing.T) {
	f, err := os.Open("../../../testdata/ig-versions/v0.51.0/trace_dns_sample.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := aggregateDNS(f, attrib.Opts{Container: "egress-target"})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.HostnamesFor("1.1.1.1"); !reflect.DeepEqual(got, []string{"api.example.com"}) {
		t.Errorf("1.1.1.1 -> %v, want [api.example.com]", got)
	}
	if got := c.HostnamesFor("10.0.0.5"); !reflect.DeepEqual(got, []string{"db.internal"}) {
		t.Errorf("10.0.0.5 -> %v, want [db.internal]", got)
	}
	// The other container's mapping must not leak through the selector.
	if c.HostnamesFor("203.0.113.7") != nil {
		t.Errorf("other-container mapping leaked: %v", c.HostnamesByIP)
	}
	if len(c.Resolvers) != 1 || c.Resolvers[0].Addr != "10.0.0.2" || c.Resolvers[0].Port != 53 {
		t.Errorf("Resolvers = %+v, want one 10.0.0.2:53", c.Resolvers)
	}
}
