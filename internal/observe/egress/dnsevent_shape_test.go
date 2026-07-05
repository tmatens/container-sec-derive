package egress

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// #285: defend the two trace_dns field-shape traps CLAUDE.md documents. At the
// pinned v0.51.0 the real event serializes `qr_raw` as a JSON bool (not the int
// the gadget config claims) and `nameserver` as an l4endpoint object (not a
// string). Getting either wrong fails json.Unmarshal for the WHOLE event, so a
// silent regression empties the DNS correlation with no error surfaced. The
// existing TestDNSSampleFixtureParses proves the fixture parses; these pin the
// two shapes explicitly, so a fixture "simplified" to the config's wrong types —
// or a parser changed to match the config — breaks the build instead.

const dnsFixturePath = "../../../testdata/ig-versions/v0.51.0/trace_dns_sample.ndjson"

func TestDNSFixture_RawShapesMatchRealV051(t *testing.T) {
	data, err := os.ReadFile(dnsFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	scan := bufio.NewScanner(bytes.NewReader(data))
	lines := 0
	for scan.Scan() {
		line := bytes.TrimSpace(scan.Bytes())
		if len(line) == 0 {
			continue
		}
		lines++
		var raw struct {
			QRRaw      json.RawMessage `json:"qr_raw"`
			Nameserver json.RawMessage `json:"nameserver"`
		}
		if err := json.Unmarshal(line, &raw); err != nil {
			t.Fatalf("line %d: %v", lines, err)
		}
		// qr_raw must be a JSON boolean literal, never a number.
		if s := string(bytes.TrimSpace(raw.QRRaw)); s != "true" && s != "false" {
			t.Errorf("line %d: qr_raw = %q, want a JSON bool — the v0.51.0 real shape (the gadget config's int is wrong)", lines, s)
		}
		// nameserver, when present, must be a JSON object (l4endpoint), never a string.
		if b := bytes.TrimSpace(raw.Nameserver); len(b) > 0 && b[0] != '{' {
			t.Errorf("line %d: nameserver = %s, want a JSON object (l4endpoint), not a string", lines, b)
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if lines == 0 {
		t.Fatal("fixture had no lines")
	}
}

func TestDNSEvent_QRRawBoolContract(t *testing.T) {
	// The parser types qr_raw as bool because the real event is bool. A bool must
	// parse and set Response; an int must be REJECTED — if the int ever parses,
	// the parser drifted back to the config's wrong type and every real event
	// would fail.
	var ok dnsEvent
	if err := json.Unmarshal([]byte(`{"qr":"R","qr_raw":true,"name":"a.","id":1}`), &ok); err != nil {
		t.Fatalf("bool qr_raw should parse: %v", err)
	}
	if !ok.Response {
		t.Error("qr_raw:true should set Response")
	}
	var bad dnsEvent
	if err := json.Unmarshal([]byte(`{"qr":"R","qr_raw":1,"name":"a."}`), &bad); err == nil {
		t.Error("qr_raw as an int must be rejected (the field is bool at v0.51.0); the parser drifted to the config's wrong type")
	}
}

func TestDNSEvent_NameserverTypeIgnored_ResolverFromEndpoints(t *testing.T) {
	// nameserver is deliberately unparsed — the resolver derives from src/dst — so
	// its type (object in the real event, string in the config) must never break
	// the event. Both forms parse and yield the same resolver.
	object := `{"qr":"Q","qr_raw":false,"name":"a.","dst":{"addr":"10.0.0.2","port":53,"version":4},"nameserver":{"addr":"10.0.0.2","version":4}}`
	str := `{"qr":"Q","qr_raw":false,"name":"a.","dst":{"addr":"10.0.0.2","port":53,"version":4},"nameserver":"10.0.0.2"}`
	for _, in := range []string{object, str} {
		var e dnsEvent
		if err := json.Unmarshal([]byte(in), &e); err != nil {
			t.Fatalf("nameserver type must not break parsing: %v\n%s", err, in)
		}
		if r := e.Resolver(); r.Addr != "10.0.0.2" || r.Port != 53 {
			t.Errorf("resolver = %+v, want 10.0.0.2:53 (derived from dst, not nameserver)", r)
		}
	}
}
