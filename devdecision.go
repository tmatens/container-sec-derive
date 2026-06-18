package main

import "github.com/tmatens/container-sec-derive/internal/sidecar"

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
//
// Foot-gun (issue #92): csd reports the devices the workload *opened*. A device
// the workload never touched during the window is not surfaced — the standing
// Caveat (workload-bounded, not a correctness proof) applies to devices exactly
// as it does to caps and writable paths.
func deviceToRecommendation(devices []string) sidecar.DeviceRecommendation {
	rec := sidecar.DeviceRecommendation{Devices: append([]string(nil), devices...)}
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
