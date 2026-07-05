package egress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/ig"
	"github.com/tmatens/container-sec-derive/internal/observe"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// dnsCorrelation is the aggregate of a trace_dns stream for one target: the
// IP->hostnames map derived from response packets and the distinct resolver
// endpoints the workload used. It is the bridge from trace_dns to the egress
// allowlist (issue #159) — hostnames annotate the IP destinations trace_tcp
// recorded, and the resolvers are the UDP/53 destinations trace_tcp cannot see
// (and that a default-DROP allowlist must permit or all name resolution
// breaks). It is union-only: a hostname resolves to the same IPs regardless of
// which replica issued the query, and resolver config is infra-level rather
// than per-replica, so unlike egressObservation there is no per-replica split.
type dnsCorrelation struct {
	HostnamesByIP map[string][]string  // resolved IP -> sorted distinct hostnames
	Resolvers     []sidecar.EgressDest // sorted distinct resolver (addr, port) endpoints
	EventCount    int                  // trace_dns events counted post-filter (queries + responses)
	Dropped       int                  // ig ringbuf-lost samples (live; 0 in fixture)
}

// HostnamesFor returns the hostnames that resolved to addr, or nil. Safe on a
// nil correlation so callers need not nil-check before annotating an egress
// destination.
func (c *dnsCorrelation) HostnamesFor(addr string) []string {
	if c == nil {
		return nil
	}
	return c.HostnamesByIP[addr]
}

// aggregateDNS reads trace_dns NDJSON from r, keeps events matching the target
// selector, and builds the IP->hostnames map (from response packets) plus the
// distinct resolver-endpoint set (from both queries and responses — the
// resolver is the peer either way, see dnsEvent.Resolver). A malformed line is
// a hard error, matching aggregateEgress (the deep-review L3 contract: the
// pinned ig emits clean one-event-per-line NDJSON).
//
// It does NOT re-run the >1-replica ambiguity guard: this is the auxiliary DNS
// signal of an --observe egress run, and aggregateEgress already enforces that
// guard on the primary trace_tcp stream. The correlation is union-only by
// design, so there is nothing replica-scoped to be ambiguous about.
func aggregateDNS(r io.Reader, opts attrib.Opts) (*dnsCorrelation, error) {
	hostSets := map[string]map[string]struct{}{}   // ip -> set of names
	resolverSet := map[string]sidecar.EgressDest{} // key -> resolver endpoint
	count := 0
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64*1024), observe.MaxScanLineBytes)
	for scan.Scan() {
		line := scan.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev dnsEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("parse trace_dns event: %w", err)
		}
		if !opts.MatchesRuntime(ev.Runtime.ContainerID, ev.Runtime.ContainerName, ev.Runtime.ContainerImage) {
			continue
		}
		count++

		// Resolver endpoint (the UDP/53 destination trace_tcp misses). Recorded
		// as observed — not assumed to be port 53 — so DoT/non-standard ports
		// surface honestly.
		if res := ev.Resolver(); res.Addr != "" && res.Port != 0 {
			dest := sidecar.EgressDest{Addr: res.Addr, Port: res.Port, Version: res.Version}
			resolverSet[dest.String()] = dest
		}

		// IP->hostname mapping: only response packets carry resolved addresses.
		// Drop names that are not valid hostnames (#202): the observed container
		// controls the query names, and an unsanitized name would flow into a
		// root-applied nftables/NetworkPolicy comment. A dropped annotation costs
		// only a comment — the IP allowlist itself is trace_tcp-derived.
		if !ev.IsResponse() || ev.Name == "" || !validHostname(ev.Name) {
			continue
		}
		for _, ip := range ev.Addresses {
			if hostSets[ip] == nil {
				hostSets[ip] = map[string]struct{}{}
			}
			hostSets[ip][ev.Name] = struct{}{}
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}

	c := &dnsCorrelation{
		HostnamesByIP: make(map[string][]string, len(hostSets)),
		EventCount:    count,
	}
	for ip, set := range hostSets {
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		c.HostnamesByIP[ip] = names
	}
	c.Resolvers = sortedDests(resolverSet)
	return c, nil
}

// observeDNS spawns `ig run trace_dns --output json` and builds the DNS
// correlation for the lifetime of ctx. It is observeEgress with aggregateDNS
// swapped in and the trace_dns gadget — the same stderr-drain + ringbuf-loss
// accounting and early-error kill; only the gadget and aggregator differ. It
// runs concurrently with observeEgress (see ProduceEgressObservation), so it
// must not share state with it; it returns its own *dnsCorrelation.
func observeDNS(ctx context.Context, igBin string, opts attrib.Opts, stderrSink io.Writer) (*dnsCorrelation, error) {
	corr, lost, err := ig.RunGadget(ctx, igBin, ig.TraceDnsGadget, []string{"--output", "json"}, stderrSink,
		func(stdout io.Reader) (*dnsCorrelation, error) { return aggregateDNS(stdout, opts) })
	if err != nil {
		return nil, err
	}
	if corr != nil {
		corr.Dropped = lost
	}
	return corr, nil
}
