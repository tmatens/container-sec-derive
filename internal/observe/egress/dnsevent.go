package egress

import (
	"bytes"
	"encoding/json"
	"strings"
)

// The v0.8 egress observer's DNS/hostname follow-up (issue #159) consumes the
// built-in trace_dns gadget at PINNED_IG_VERSION as a second signal alongside
// trace_tcp. trace_tcp is TCP-only and IP-based (it reports the resolved IP a
// connect() reached, not the hostname the app asked for, and never sees DNS,
// which is UDP/53). trace_dns closes both gaps: its response packets carry
// `name -> addresses`, which inverts to the IP->hostname map that annotates the
// egress allowlist, and its query packets reveal the resolver endpoint that a
// default-DROP allowlist must permit or all name resolution breaks.
//
// The field shapes below are confirmed against a REAL v0.51.0 trace_dns event
// captured on a live runner (issue #159, the smoke's standalone probe), not just
// the gadget config — two shapes the config survey got wrong and that silently
// broke the first live run: `qr_raw` serializes as a JSON bool (not an int), and
// `nameserver` is an l4endpoint object (not a string). Getting either type wrong
// fails json.Unmarshal for the whole event, so every DNS event was rejected and
// the live correlation came back empty. As with tcpEvent the parser is lenient:
// hand-rolled fixtures need not carry every field. l4Endpoint is shared with
// tcpEvent (egressevent.go) — DNS endpoints use the same `l4endpoint` template,
// only with proto 17 (UDP) instead of 6 (TCP).

// dnsEvent is the subset of ig trace_dns fields the egress DNS correlation
// consumes. `addresses` is the comma-separated A/AAAA list ig emits (per the
// gadget config: "Comma-separated list of IP addresses ... populated only on
// DNS response packets"); it is split into Addresses. Dst is the resolver
// endpoint contacted for a query (the destination a query() reaches), the
// source endpoint for a response.
type dnsEvent struct {
	Name      string // domain queried, trailing dot trimmed
	Addresses []string
	Qtype     string // record type: A, AAAA, ...
	Rcode     string // response code text: NoError, NXDomain, ...
	ID        string // DNS query/response id, matches a response to its query
	Response  bool   // qr: true for a response packet, false for a query
	Src       l4Endpoint
	Dst       l4Endpoint // resolver endpoint for a query; client for a response
	Proc      struct {
		Comm string
		Pid  int
	}
	Runtime struct {
		ContainerID    string
		ContainerName  string
		ContainerImage string
		RuntimeName    string
	}
}

func (e *dnsEvent) UnmarshalJSON(data []byte) error {
	type endpointT struct {
		Addr    string `json:"addr"`
		Port    int    `json:"port"`
		Version int    `json:"version"`
	}
	type procT struct {
		Comm string `json:"comm"`
		Pid  int    `json:"pid"`
	}
	type runtimeT struct {
		ContainerID    string `json:"containerId"`
		ContainerName  string `json:"containerName"`
		ContainerImage string `json:"containerImageName"`
		RuntimeName    string `json:"runtimeName"`
	}
	var wire struct {
		Name      string          `json:"name"`
		Addresses string          `json:"addresses"`
		Qtype     string          `json:"qtype"`
		Rcode     string          `json:"rcode"`
		ID        json.RawMessage `json:"id"` // number or string across ig builds
		QR        string          `json:"qr"`
		QRRaw     bool            `json:"qr_raw"` // v0.51.0 serializes qr_raw as a bool (true=response)
		Src       endpointT       `json:"src"`
		Dst       endpointT       `json:"dst"`
		// `nameserver` is an l4endpoint object in v0.51.0, not a string; csd
		// derives the resolver from src/dst (Resolver()) so it is intentionally
		// left unparsed — declaring no field lets json ignore the object cleanly.
		Proc    procT    `json:"proc"`
		Runtime runtimeT `json:"runtime"`
		// Flat fallbacks: comm/pid at the top level when there is no `proc`
		// envelope (the older ig serialization). The nested form wins.
		FlatComm string `json:"comm"`
		FlatPid  int    `json:"pid"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	e.Name = normalizeDNSName(wire.Name)
	e.Addresses = splitAddresses(wire.Addresses)
	e.Qtype = wire.Qtype
	e.Rcode = wire.Rcode
	e.ID = normalizeID(wire.ID)
	// qr: v0.51.0 renders the column as "Q"/"R" with a boolean qr_raw sibling
	// (true = response). Treat either signal as authoritative.
	e.Response = wire.QRRaw || isResponseLabel(wire.QR)
	e.Src = l4Endpoint{Addr: wire.Src.Addr, Port: wire.Src.Port, Version: wire.Src.Version}
	e.Dst = l4Endpoint{Addr: wire.Dst.Addr, Port: wire.Dst.Port, Version: wire.Dst.Version}
	e.Proc.Comm, e.Proc.Pid = wire.Proc.Comm, wire.Proc.Pid
	if e.Proc.Comm == "" {
		e.Proc.Comm = wire.FlatComm
	}
	if e.Proc.Pid == 0 {
		e.Proc.Pid = wire.FlatPid
	}
	e.Runtime.ContainerID = wire.Runtime.ContainerID
	e.Runtime.ContainerName = wire.Runtime.ContainerName
	e.Runtime.ContainerImage = wire.Runtime.ContainerImage
	e.Runtime.RuntimeName = wire.Runtime.RuntimeName
	return nil
}

// IsResponse reports whether the event is a DNS response packet. Only responses
// carry the resolved addresses, so the IP->hostname correlation keys off them.
func (e dnsEvent) IsResponse() bool { return e.Response }

// Resolver returns the resolver endpoint a query reached: for a query the dst,
// for a response the src (the resolver is the peer in both directions). It is
// the (addr, port) a default-DROP egress allowlist must permit so the workload
// can still resolve names. Returns the zero endpoint when neither side carries
// a usable address.
func (e dnsEvent) Resolver() l4Endpoint {
	if e.Response {
		if e.Src.Addr != "" {
			return e.Src
		}
		return e.Dst
	}
	if e.Dst.Addr != "" {
		return e.Dst
	}
	return e.Src
}

// normalizeDNSName trims the trailing dot DNS wire/format names carry
// ("example.com." -> "example.com") and lowercases for stable correlation.
func normalizeDNSName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

// splitAddresses parses the comma-separated addresses field into a slice,
// dropping blanks. Returns nil (not an empty slice) when there are none, so a
// query packet — which never populates addresses — stays clearly empty.
func splitAddresses(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// normalizeID renders the DNS id as a stable string regardless of whether ig
// serialized it as a JSON number or a quoted string. Used only to pair a
// response with its query, so the exact representation is immaterial as long as
// it is consistent within a run.
func normalizeID(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	}
	return string(raw)
}

func isResponseLabel(qr string) bool {
	switch strings.ToLower(strings.TrimSpace(qr)) {
	case "r", "response", "resp", "answer":
		return true
	default:
		return false
	}
}
