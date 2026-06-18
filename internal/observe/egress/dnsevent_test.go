package egress

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestDNSEventResponseUnmarshal(t *testing.T) {
	// A response packet: carries the resolved addresses, qr=R, the resolver as
	// src. Name has the trailing dot trace_dns emits and mixed case.
	const line = `{"qr":"R","qr_raw":true,"name":"API.Example.com.","qtype":"A","rcode":"NoError","addresses":"1.1.1.1","id":4660,"src":{"addr":"10.0.0.2","port":53,"proto":17,"version":4},"dst":{"addr":"172.17.0.3","port":40555,"proto":17,"version":4},"nameserver":{"addr":"10.0.0.2","version":4},"proc":{"comm":"app","pid":4242},"runtime":{"runtimeName":"docker","containerId":"abc","containerName":"web","containerImageName":"web:1"}}`
	var e dnsEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatal(err)
	}
	if !e.IsResponse() {
		t.Errorf("IsResponse = false, want true")
	}
	if e.Name != "api.example.com" {
		t.Errorf("Name = %q, want normalized api.example.com", e.Name)
	}
	if !reflect.DeepEqual(e.Addresses, []string{"1.1.1.1"}) {
		t.Errorf("Addresses = %v, want [1.1.1.1]", e.Addresses)
	}
	if e.ID != "4660" {
		t.Errorf("ID = %q, want 4660", e.ID)
	}
	// Resolver of a response is the src endpoint (the resolver is the peer).
	if r := e.Resolver(); r.Addr != "10.0.0.2" || r.Port != 53 {
		t.Errorf("Resolver = %+v, want 10.0.0.2:53", r)
	}
	if e.Runtime.ContainerName != "web" || e.Runtime.ContainerImage != "web:1" {
		t.Errorf("runtime = %+v", e.Runtime)
	}
}

func TestDNSEventQueryUnmarshal(t *testing.T) {
	// A query packet: no addresses, qr=Q, resolver is the dst.
	const line = `{"qr":"Q","qr_raw":false,"name":"db.internal.","qtype":"A","id":22136,"src":{"addr":"172.17.0.3","port":40556,"proto":17,"version":4},"dst":{"addr":"10.0.0.2","port":53,"proto":17,"version":4},"proc":{"comm":"app","pid":4242}}`
	var e dnsEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatal(err)
	}
	if e.IsResponse() {
		t.Errorf("IsResponse = true, want false for a query")
	}
	if len(e.Addresses) != 0 {
		t.Errorf("Addresses = %v, want empty for a query", e.Addresses)
	}
	if r := e.Resolver(); r.Addr != "10.0.0.2" || r.Port != 53 {
		t.Errorf("Resolver = %+v, want 10.0.0.2:53 (the dst) for a query", r)
	}
}

func TestDNSEventMultiAddressSplit(t *testing.T) {
	// Two AAAA answers, comma-separated with the space ig inserts.
	const line = `{"qr":"R","qr_raw":true,"name":"cdn.example.com","qtype":"AAAA","addresses":"2606:4700:4700::1111, 2606:4700:4700::1001","id":33007}`
	var e dnsEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatal(err)
	}
	want := []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}
	if !reflect.DeepEqual(e.Addresses, want) {
		t.Errorf("Addresses = %v, want %v", e.Addresses, want)
	}
}

func TestDNSEventEmptyAddressesNXDomain(t *testing.T) {
	// NXDomain response: addresses is the empty string and must parse to nil,
	// not [""], so the correlation never maps a hostname to a blank IP.
	const line = `{"qr":"R","qr_raw":true,"name":"missing.example.com.","rcode":"NXDomain","addresses":"","id":40001}`
	var e dnsEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatal(err)
	}
	if e.Addresses != nil {
		t.Errorf("Addresses = %v, want nil for NXDomain", e.Addresses)
	}
	if e.Rcode != "NXDomain" {
		t.Errorf("Rcode = %q, want NXDomain", e.Rcode)
	}
}

func TestDNSEventResponseDetectionFallbacks(t *testing.T) {
	// qr_raw alone (no qr string), and qr string alone (no qr_raw) must both
	// classify a response.
	for _, line := range []string{
		`{"qr_raw":true,"name":"a.test"}`,
		`{"qr":"R","name":"a.test"}`,
		`{"qr":"response","name":"a.test"}`,
	} {
		var e dnsEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if !e.IsResponse() {
			t.Errorf("IsResponse = false for %q, want true", line)
		}
	}
	// A bare query must not be classified as a response.
	var q dnsEvent
	if err := json.Unmarshal([]byte(`{"qr":"Q","qr_raw":false,"name":"a.test"}`), &q); err != nil {
		t.Fatal(err)
	}
	if q.IsResponse() {
		t.Errorf("IsResponse = true for a query, want false")
	}
}

func TestDNSEventIDStringAndNumber(t *testing.T) {
	// ig builds may serialize the DNS id as a number or a quoted hex string;
	// both must normalize to a non-empty, stable token. A missing id is empty.
	for _, c := range []struct{ in, want string }{
		{`{"id":4660}`, "4660"},
		{`{"id":"0x1234"}`, "0x1234"},
		{`{}`, ""},
		{`{"id":null}`, ""},
	} {
		var e dnsEvent
		if err := json.Unmarshal([]byte(c.in), &e); err != nil {
			t.Fatal(err)
		}
		if e.ID != c.want {
			t.Errorf("ID for %q = %q, want %q", c.in, e.ID, c.want)
		}
	}
}

func TestDNSEventFlatProcFallback(t *testing.T) {
	const line = `{"qr":"Q","name":"a.test","comm":"wget","pid":99}`
	var e dnsEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatal(err)
	}
	if e.Proc.Comm != "wget" || e.Proc.Pid != 99 {
		t.Errorf("flat proc = %+v, want wget/99", e.Proc)
	}
}

// TestDNSSampleFixtureParses guards the committed fixture: every line must
// decode, and the response lines must carry the addresses the aggregation/
// correlation PR (issue #159) depends on.
func TestDNSSampleFixtureParses(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/ig-versions/v0.51.0/trace_dns_sample.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	scan := bufio.NewScanner(bytes.NewReader(data))
	responses, withAddrs := 0, 0
	for scan.Scan() {
		line := bytes.TrimSpace(scan.Bytes())
		if len(line) == 0 {
			continue
		}
		var e dnsEvent
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("fixture line failed to parse: %v\n%s", err, line)
		}
		if e.IsResponse() {
			responses++
			if len(e.Addresses) > 0 {
				withAddrs++
			}
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if responses == 0 || withAddrs == 0 {
		t.Errorf("fixture has %d responses, %d with addresses; want both > 0", responses, withAddrs)
	}
}
