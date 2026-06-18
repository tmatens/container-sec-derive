package capadd

import (
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
)

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
		obs, err := AggregateCapadd(strings.NewReader(data), attrib.Opts{}, DangerousCaps)
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
