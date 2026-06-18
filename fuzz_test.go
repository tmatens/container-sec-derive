package main

import (
	"bytes"
	"encoding/json"
	"testing"

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
