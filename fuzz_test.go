package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The fuzz targets below harden csd's parsers of untrusted subprocess output —
// ig's NDJSON event stream and `docker inspect`'s .Mounts JSON. The tool runs
// root-equivalent and parses whatever ig/docker emit, so a malformed line must
// never panic the process. `go test` runs the seed corpus on every run (cheap);
// `go test -fuzz=Fuzz...` extends them on demand.

func FuzzFileEventUnmarshal(f *testing.F) {
	f.Add(`{"syscall":"openat","flags_raw":65,"fpath":"/x","fname":"x","proc":{"comm":"a","pid":1},"runtime":{"containerId":"c","containerName":"n","containerImageName":"i"}}`)
	f.Add(`{"timestamp_raw":123456789,"flags":"O_WRONLY|O_CREAT","error_raw":13}`)
	f.Add(`{}`)
	f.Add(`{"flags_raw":-1,"timestamp":"not-a-number"}`)
	f.Fuzz(func(t *testing.T, data string) {
		var e fileEvent
		_ = json.Unmarshal([]byte(data), &e) // errors are fine; a panic is not
		// Exercise the accessor methods the pipeline calls on every event.
		_ = e.IsWrite()
		_ = e.Path()
	})
}

func FuzzCapEventUnmarshal(f *testing.F) {
	f.Add(`{"cap":"CHOWN","capable":true,"syscall":"chown","proc":{"comm":"a","pid":1},"runtime":{"containerId":"c"}}`)
	f.Add(`{"timestamp_raw":123,"capable":false}`)
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, data string) {
		var e capEvent
		_ = json.Unmarshal([]byte(data), &e)
	})
}

func FuzzParseMountDestinations(f *testing.F) {
	f.Add(`[{"Destination":"/a"},{"Destination":"/b","Source":"x"}]`)
	f.Add(`null`)
	f.Add(`[]`)
	f.Add(`not json`)
	f.Add(`[{"Destination":123}]`)
	f.Fuzz(func(t *testing.T, data string) {
		dests, err := parseMountDestinations([]byte(data))
		// On success, every returned destination must be non-empty (the
		// parser's documented contract) — a fuzz-found violation is a bug.
		if err == nil {
			for _, d := range dests {
				if strings.TrimSpace(d) == "" {
					t.Errorf("parseMountDestinations returned an empty destination for input %q", data)
				}
			}
		}
	})
}
