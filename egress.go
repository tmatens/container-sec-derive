package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
)

// egressDest is one distinct outbound destination the workload contacted: a
// resolved IP address + port (the allowlist key). The IP is what connect()
// observed — not the hostname the app asked for (see the brittleness caveat in
// issue #136); a trace_dns correlation for hostnames is a deferred enhancement.
type egressDest struct {
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Version int    `json:"version,omitempty"` // 4 or 6
}

// String renders the destination as a canonical host:port key, IPv6-bracketed
// (net.JoinHostPort), used both as the aggregation key and for stable sorting.
func (d egressDest) String() string {
	return net.JoinHostPort(d.Addr, strconv.Itoa(d.Port))
}

// egressObservation is the egress observer's aggregate: the distinct outbound
// destinations contacted (unioned and per-replica) plus the count of connect
// events behind them. It mirrors deviceObservation/writeObservation so the
// sidecar/confidence/multi-replica machinery carries over; the decision layer
// (the allowlist recommendation) sits on top in a later change.
type egressObservation struct {
	Dests           []egressDest            // sorted union of distinct destinations
	PerReplica      map[string][]egressDest // replica id (or name) -> sorted dests
	EventCount      int                     // connect events counted post-filter
	PerReplicaCount map[string]int          // connect-event count per replica
	Stats           map[string]*egressStats // dest.String() -> per-dest detail
	Dropped         int                     // ig ringbuf-lost samples (live; 0 in fixture)
	Image           string                  // first observed container image
}

// egressStats collapses N connect events to one destination into the numbers
// the sidecar's egress section needs. Mirrors deviceStats.
type egressStats struct {
	eventCount  int
	commSamples map[string]struct{}
}

// sortedDests returns the destinations in a stable order (by address, then
// port) so the union and per-replica lists are deterministic.
func sortedDests(m map[string]egressDest) []egressDest {
	out := make([]egressDest, 0, len(m))
	for _, d := range m {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// aggregateEgress reads trace_tcp NDJSON from r, keeps events that match the
// target selector (aggregateOpts.matchesRuntime) and are outbound connect()s
// (tcpEvent.IsConnect) with a complete destination, and collects the distinct
// destinations per replica and unioned. Replica identity and the >1-replica
// ambiguity guard mirror aggregateDevices/aggregateWrites exactly. A malformed
// line is a hard error (the deep-review L3 contract — the pinned ig emits clean
// one-event-per-line NDJSON, so a parse failure means corrupt input).
func aggregateEgress(r io.Reader, opts aggregateOpts) (*egressObservation, error) {
	union := map[string]egressDest{}
	perReplica := map[string]map[string]egressDest{}
	perReplicaCount := map[string]int{}
	perReplicaName := map[string]string{}
	stats := map[string]*egressStats{}
	count := 0
	image := ""
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	for scan.Scan() {
		line := scan.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev tcpEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("parse trace_tcp event: %w", err)
		}
		if !opts.matchesRuntime(ev.Runtime.ContainerID, ev.Runtime.ContainerName, ev.Runtime.ContainerImage) {
			continue
		}
		if !ev.IsConnect() {
			continue
		}
		if ev.Dst.Addr == "" || ev.Dst.Port == 0 {
			// Incomplete endpoint — nothing actionable for an allowlist.
			continue
		}
		dest := egressDest{Addr: ev.Dst.Addr, Port: ev.Dst.Port, Version: ev.Dst.Version}
		key := dest.String()
		count++
		if image == "" {
			image = ev.Runtime.ContainerImage
		}
		union[key] = dest
		rid := ev.Runtime.ContainerID
		if rid == "" {
			rid = ev.Runtime.ContainerName
		}
		if perReplica[rid] == nil {
			perReplica[rid] = map[string]egressDest{}
		}
		perReplica[rid][key] = dest
		perReplicaCount[rid]++
		if ev.Runtime.ContainerName != "" {
			perReplicaName[rid] = ev.Runtime.ContainerName
		}
		st := stats[key]
		if st == nil {
			st = &egressStats{commSamples: map[string]struct{}{}}
			stats[key] = st
		}
		st.eventCount++
		if comm := strings.TrimSpace(ev.Proc.Comm); comm != "" {
			st.commSamples[comm] = struct{}{}
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}

	// Ambiguity: the selector (--image, or a too-short --container prefix)
	// matched >1 replica without --all-matching. Mirrors the cap/fs/device
	// aggregators — the tool refuses to silently union the egress destinations
	// of replicas the user didn't opt into aggregating.
	if opts.ambiguous(len(perReplica)) {
		labels := make([]string, 0, len(perReplica))
		for rid := range perReplica {
			if name := perReplicaName[rid]; name != "" {
				labels = append(labels, fmt.Sprintf("%s (%s)", name, rid))
			} else {
				labels = append(labels, rid)
			}
		}
		sort.Strings(labels)
		return nil, opts.newAmbiguousSelectionError(labels)
	}

	obs := &egressObservation{
		Dests:           sortedDests(union),
		PerReplica:      map[string][]egressDest{},
		EventCount:      count,
		PerReplicaCount: perReplicaCount,
		Stats:           stats,
		Image:           image,
	}
	for rid, set := range perReplica {
		obs.PerReplica[rid] = sortedDests(set)
	}
	return obs, nil
}
