package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// egressObservation is the egress observer's aggregate: the distinct outbound
// destinations contacted (unioned and per-replica) plus the count of connect
// events behind them. It mirrors deviceObservation/writeObservation so the
// sidecar/confidence/multi-replica machinery carries over; the decision layer
// (the allowlist recommendation) sits on top in a later change.
type egressObservation struct {
	Dests           []sidecar.EgressDest            // sorted union of distinct destinations
	PerReplica      map[string][]sidecar.EgressDest // replica id (or name) -> sorted dests
	EventCount      int                             // connect events counted post-filter
	PerReplicaCount map[string]int                  // connect-event count per replica
	Stats           map[string]*egressStats         // dest.String() -> per-dest detail
	Dropped         int                             // ig ringbuf-lost samples (live; 0 in fixture)
	Image           string                          // first observed container image
}

// egressStats collapses N connect events to one destination into the numbers
// the sidecar's egress section needs. Mirrors deviceStats.
type egressStats struct {
	eventCount  int
	commSamples map[string]struct{}
}

// sortedDests returns the destinations in a stable order (by address, then
// port) so the union and per-replica lists are deterministic.
func sortedDests(m map[string]sidecar.EgressDest) []sidecar.EgressDest {
	out := make([]sidecar.EgressDest, 0, len(m))
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
func aggregateEgress(r io.Reader, opts attrib.Opts) (*egressObservation, error) {
	union := map[string]sidecar.EgressDest{}
	perReplica := map[string]map[string]sidecar.EgressDest{}
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
		if !opts.MatchesRuntime(ev.Runtime.ContainerID, ev.Runtime.ContainerName, ev.Runtime.ContainerImage) {
			continue
		}
		if !ev.IsConnect() {
			continue
		}
		if ev.Dst.Addr == "" || ev.Dst.Port == 0 {
			// Incomplete endpoint — nothing actionable for an allowlist.
			continue
		}
		dest := sidecar.EgressDest{Addr: ev.Dst.Addr, Port: ev.Dst.Port, Version: ev.Dst.Version}
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
			perReplica[rid] = map[string]sidecar.EgressDest{}
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
	if opts.Ambiguous(len(perReplica)) {
		labels := make([]string, 0, len(perReplica))
		for rid := range perReplica {
			if name := perReplicaName[rid]; name != "" {
				labels = append(labels, fmt.Sprintf("%s (%s)", name, rid))
			} else {
				labels = append(labels, rid)
			}
		}
		sort.Strings(labels)
		return nil, opts.NewAmbiguousSelectionError(labels)
	}

	obs := &egressObservation{
		Dests:           sortedDests(union),
		PerReplica:      map[string][]sidecar.EgressDest{},
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
