package main

// deviceRecommendation is the v0.3 device-decomposition decision derived from
// the observed non-default device nodes:
//   - Devices is the minimum explicit device-grant list (compose `devices:`,
//     `--device` for docker run). Unlike the fs tmpfs recommendation, device
//     nodes are NOT collapsed to ancestors: a grant is per-node, so
//     /dev/dri/card0 and /dev/dri/renderD128 are listed separately.
//   - DerivedCaps are capabilities a granted device is known to imply, surfaced
//     as hints. They are deliberately conservative (see deviceCapHints); the
//     privileged-composition path (issue #92, capstone PR) prefers the cap set
//     actually observed by trace_capabilities over this static table.
//
// Foot-gun (issue #92): csd reports the devices the workload *opened*. A device
// the workload never touched during the window is not surfaced — the standing
// Caveat (workload-bounded, not a correctness proof) applies to devices exactly
// as it does to caps and writable paths.
type deviceRecommendation struct {
	Devices     []string `json:"devices"`
	DerivedCaps []string `json:"derived_caps,omitempty"`
}

// deviceCapHints maps a device node to a capability that opening/using it is
// well-established to require. Kept intentionally minimal and evidence-backed —
// only mappings that are unambiguous get an entry, to avoid false precision in
// the standalone `--observe devices` output. Creating or configuring a tun/tap
// interface through /dev/net/tun requires CAP_NET_ADMIN; that is the one clean,
// universally-true mapping, so it is the only seed. The composition path uses
// observed caps instead of this table (issue #92 open question 3).
var deviceCapHints = map[string]string{
	"/dev/net/tun": "CAP_NET_ADMIN",
}

// deviceToRecommendation synthesizes the minimum device-grant list and any
// derived-capability hints from the observed (sorted, deduplicated) device
// nodes. devices is expected sorted, as aggregateDevices returns it; the output
// Devices slice preserves that order and DerivedCaps is sorted+deduplicated.
func deviceToRecommendation(devices []string) deviceRecommendation {
	rec := deviceRecommendation{Devices: append([]string(nil), devices...)}
	caps := map[string]struct{}{}
	for _, d := range devices {
		if c, ok := deviceCapHints[d]; ok {
			caps[c] = struct{}{}
		}
	}
	if len(caps) > 0 {
		rec.DerivedCaps = sortedKeys(caps)
	}
	return rec
}
