package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/observe/caps"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// The fuzz targets below harden csd's parsers of untrusted subprocess output —
// ig's NDJSON event stream and `docker inspect`'s .Mounts JSON. The tool runs
// root-equivalent and parses whatever ig/docker emit, so a malformed line must
// never panic the process. `go test` runs the seed corpus on every run (cheap);
// `go test -fuzz=Fuzz...` extends them on demand.

func FuzzCapEventUnmarshal(f *testing.F) {
	f.Add(`{"cap":"CHOWN","capable":true,"syscall":"chown","proc":{"comm":"a","pid":1},"runtime":{"containerId":"c"}}`)
	f.Add(`{"timestamp_raw":123,"capable":false}`)
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, data string) {
		var e caps.CapEvent
		_ = json.Unmarshal([]byte(data), &e)
	})
}

// FuzzAggregateCapadd hardens the v0.4 capadd aggregation LOOP (not just the
// CapEvent unmarshal, which FuzzCapEventUnmarshal already covers): the line
// scanner, the held/init/denied filtering, the per-cap syscall maps, and the
// multi-replica bookkeeping. A malformed ig stream must never panic, and the
// recorded EventCount must always equal the sum of per-cap held events.
func FuzzAggregateCapadd(f *testing.F) {
	f.Add(`{"cap":"SYS_ADMIN","capable":true,"syscall":"mount","proc":{"comm":"x","pid":1},"runtime":{"containerId":"c","containerImageName":"i"}}` + "\n")
	f.Add(`{"cap":"NET_RAW","capable":false,"syscall":"socket"}` + "\n" + `{"cap":"NET_RAW","capable":true,"syscall":"socket","proc":{"comm":"runc:[1]","pid":1}}` + "\n")
	f.Add("{}\n{}\n")
	f.Add("not json\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		obs, err := aggregateCapadd(strings.NewReader(data), attrib.Opts{}, dangerousCaps)
		if err != nil || obs == nil {
			return // parse / ambiguity errors are fine; a panic is not
		}
		sum := 0
		for _, u := range obs.Used {
			sum += u.events
		}
		if sum != obs.EventCount {
			t.Errorf("EventCount %d != sum of per-cap held events %d for input %q", obs.EventCount, sum, data)
		}
	})
}

// FuzzCapaddComposePatch hardens the hand-rolled compose-patch machinery shared
// by every observer's patch formatter (splitComposeLines / locateComposeService
// / findChildKeyBlock / applyRewriteSequence / markRewrites / emitUnifiedDiff).
// It rewrites a service's cap_add block by line manipulation, so a crafted /
// malformed compose file is a prime panic (index-out-of-range) target. A patch
// failure (service not found, etc.) is fine; a panic is not.
func FuzzCapaddComposePatch(f *testing.F) {
	val := &sidecar.CapaddValidation{
		Findings:           []sidecar.CapaddFinding{{Cap: "SYS_ADMIN", Used: true}},
		GrantedSetProvided: true,
		RecommendedCapAdd:  []string{"NET_RAW", "PERFMON"},
	}
	f.Add("services:\n  app:\n    image: x\n    cap_add:\n      - SYS_ADMIN\n", "app")
	f.Add("services:\n  app:\n", "app")
	f.Add("", "app")
	f.Add("not: yaml: ::::\n", "")
	f.Add("services:\n  app:\n    cap_add: []\n", "app")
	f.Fuzz(func(t *testing.T, compose, service string) {
		var buf bytes.Buffer
		_ = writeCapaddComposePatch(&buf, val, []byte(compose), "compose.yml", service)
	})
}
