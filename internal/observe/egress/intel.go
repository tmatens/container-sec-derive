package egress

import (
	"net"
	"sort"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// intel.go builds the #206 name-centric provenance view of the observed egress:
// it groups the destinations by the hostname the container resolved, tags each
// as confirmed (an address was dialed) vs. resolved-only (looked up, never
// dialed — a coverage candidate), and tags each with a publish visibility
// (public/image-intrinsic vs. the operator's own deployment-specific topology).
// It is pure data assembled from the two aggregates the egress observer already
// has — the connected (addr,port) set and the DNS IP->hostname correlation — and
// never widens the enforced allowlist (see EgressDestinationIntel).

// internalSuffixes are DNS suffixes that mark a name as the operator's own
// topology rather than a public, image-intrinsic endpoint. A name under any of
// these (or a dotless single-label name) is classified deployment-specific and
// never eligible for a public profile.
var internalSuffixes = []string{
	".lan", ".local", ".internal", ".home", ".corp", ".intranet",
	".arpa", ".test", ".example", ".invalid",
}

// isInternalName reports whether name is internal/topology (excluded from public
// output). Empty and dotless single-label names count as internal — the
// conservative default. Comparison is case-insensitive and trailing-dot
// tolerant.
func isInternalName(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if n == "" || !strings.Contains(n, ".") {
		return true
	}
	for _, s := range internalSuffixes {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// isPrivateOrReservedIP reports whether addr is a private/reserved address —
// RFC-1918 + ULA (via net.IP.IsPrivate), CGNAT 100.64.0.0/10, loopback,
// link-local, unspecified, and multicast. An unparseable address returns true
// (conservative: exclude from public output). Such an address is
// deployment-specific: it cannot be a public, image-intrinsic endpoint.
func isPrivateOrReservedIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return true
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// CGNAT 100.64.0.0/10 (RFC 6598) — not covered by IsPrivate.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return true
	}
	return false
}

// destVisibility classifies a destination for publish safety. A name is
// image-intrinsic only when it is a public FQDN AND none of its addresses are
// private/reserved (a public-looking name resolving to a private IP is a
// split-horizon internal service — deployment-specific). An IP-only destination
// is image-intrinsic only when the IP itself is public-routable. Anything else,
// and any ambiguity, is deployment-specific.
func destVisibility(name string, addrs []string) string {
	if name != "" && isInternalName(name) {
		return sidecar.EgressVisibilityDeploymentSpecific
	}
	for _, a := range addrs {
		if isPrivateOrReservedIP(a) {
			return sidecar.EgressVisibilityDeploymentSpecific
		}
	}
	if len(addrs) == 0 {
		return sidecar.EgressVisibilityDeploymentSpecific
	}
	return sidecar.EgressVisibilityImageIntrinsic
}

// buildEgressIntel assembles the provenance view from the connected destinations
// (dests) and the DNS correlation (corr, nil-safe). Named entries come first
// (sorted by name), then IP-only entries (sorted by address); the whole list is
// deterministic. Returns nil when there is nothing to report so the sidecar
// field stays omitempty-absent.
func buildEgressIntel(dests []sidecar.EgressDest, corr *dnsCorrelation) []sidecar.EgressDestinationIntel {
	// Connected addresses and the ports each was dialed on.
	connectedPorts := map[string]map[int]struct{}{}
	for _, d := range dests {
		if connectedPorts[d.Addr] == nil {
			connectedPorts[d.Addr] = map[int]struct{}{}
		}
		connectedPorts[d.Addr][d.Port] = struct{}{}
	}

	// Invert the DNS IP->names map to name->addrs, tracking which IPs carry a
	// name so IP-only (no-DNS) connects are the complement.
	nameAddrs := map[string]map[string]struct{}{}
	namedIP := map[string]struct{}{}
	if corr != nil {
		for ip, names := range corr.HostnamesByIP {
			namedIP[ip] = struct{}{}
			for _, nm := range names {
				if nameAddrs[nm] == nil {
					nameAddrs[nm] = map[string]struct{}{}
				}
				nameAddrs[nm][ip] = struct{}{}
			}
		}
	}

	var out []sidecar.EgressDestinationIntel

	// One entry per resolved name.
	names := make([]string, 0, len(nameAddrs))
	for nm := range nameAddrs {
		names = append(names, nm)
	}
	sort.Strings(names)
	for _, nm := range names {
		addrs := sortedKeys(nameAddrs[nm])
		ports := map[int]struct{}{}
		dialed := false
		for _, a := range addrs {
			if ps, ok := connectedPorts[a]; ok {
				dialed = true
				for p := range ps {
					ports[p] = struct{}{}
				}
			}
		}
		prov := sidecar.EgressProvenanceResolvedOnly
		if dialed {
			prov = sidecar.EgressProvenanceConfirmed
		}
		out = append(out, sidecar.EgressDestinationIntel{
			Name:       nm,
			Addrs:      addrs,
			Ports:      sortedInts(ports),
			Provenance: prov,
			Visibility: destVisibility(nm, addrs),
		})
	}

	// One entry per connected IP that carried no resolved name.
	ipOnly := make([]string, 0)
	for ip := range connectedPorts {
		if _, named := namedIP[ip]; !named {
			ipOnly = append(ipOnly, ip)
		}
	}
	sort.Strings(ipOnly)
	for _, ip := range ipOnly {
		out = append(out, sidecar.EgressDestinationIntel{
			Addrs:      []string{ip},
			Ports:      sortedInts(connectedPorts[ip]),
			Provenance: sidecar.EgressProvenanceConfirmed,
			Visibility: destVisibility("", []string{ip}),
		})
	}
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedInts returns the sorted keys, or nil when empty — so a resolved-only
// destination (no dialed port) carries a nil Ports that omitempty drops cleanly.
func sortedInts(m map[int]struct{}) []int {
	if len(m) == 0 {
		return nil
	}
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
