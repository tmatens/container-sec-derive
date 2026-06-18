package main

import (
	"encoding/json"
)

// The v0.8 network-egress observer (ROADMAP §v0.8, issue #136) consumes the
// built-in trace_tcp gadget at PINNED_IG_VERSION. Like the v0.2/v0.3 trace_open
// observers it shares trace_capabilities' event envelope (proc/runtime/
// timestamp_raw — see capEvent/fileEvent) and adds only the tcp-specific
// fields: the connection event type and the src/dst L4 endpoints. The signal
// and field schema were verified against a real trace_tcp event at the pin;
// see the survey in issue #136.

// l4Endpoint is the subset of ig's gadget_l4endpoint_t (the `l4endpoint`
// template) csd consumes: the decoded address string, the port, and the IP
// version. ig serializes it as {"addr","port","proto","version"} (the `proto`
// field is the L4 protocol number — always 6/TCP for trace_tcp, so we ignore
// it).
type l4Endpoint struct {
	Addr    string
	Port    int
	Version int
}

// tcpEvent is the subset of ig trace_tcp fields the egress observer consumes.
// As with capEvent/fileEvent, UnmarshalJSON is lenient: hand-rolled fixtures
// need not carry every field the live gadget emits, and it accepts both the
// nested `proc.{comm,pid}` envelope (the v0.51.0 gadget_process serialization)
// and the older flat `comm`/`pid` form shown in some ig docs.
type tcpEvent struct {
	Type string // "connect" / "accept" / "close"
	Src  l4Endpoint
	Dst  l4Endpoint
	Proc struct {
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

func (e *tcpEvent) UnmarshalJSON(data []byte) error {
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
		Type    string    `json:"type"`
		Src     endpointT `json:"src"`
		Dst     endpointT `json:"dst"`
		Proc    procT     `json:"proc"`
		Runtime runtimeT  `json:"runtime"`
		// Flat fallbacks: comm/pid at the top level when there is no `proc`
		// envelope (the older ig serialization). The nested form wins.
		FlatComm string `json:"comm"`
		FlatPid  int    `json:"pid"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	e.Type = wire.Type
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

// IsConnect reports whether the event is an outbound connect() — the only
// trace_tcp event type the egress observer keeps. `accept` is an inbound
// connection and `close` is teardown; neither is an outbound destination.
func (e tcpEvent) IsConnect() bool {
	return e.Type == "connect"
}
