package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestAggregateEgress(t *testing.T) {
	// One target replica (web-1) dialing two distinct destinations (one of them
	// twice), plus an accept and a close that must be filtered out, plus an
	// unrelated container (other-1) that attribution must exclude.
	const nd = `
{"type":"connect","dst":{"addr":"1.1.1.1","port":443,"version":4},"proc":{"comm":"app"},"runtime":{"containerId":"aaa","containerName":"web-1","containerImageName":"web:1"}}
{"type":"connect","dst":{"addr":"1.1.1.1","port":443,"version":4},"proc":{"comm":"app"},"runtime":{"containerId":"aaa","containerName":"web-1","containerImageName":"web:1"}}
{"type":"connect","dst":{"addr":"10.0.0.5","port":5432,"version":4},"proc":{"comm":"app"},"runtime":{"containerId":"aaa","containerName":"web-1","containerImageName":"web:1"}}
{"type":"accept","dst":{"addr":"10.9.9.9","port":33333,"version":4},"proc":{"comm":"app"},"runtime":{"containerId":"aaa","containerName":"web-1","containerImageName":"web:1"}}
{"type":"close","dst":{"addr":"1.1.1.1","port":443,"version":4},"proc":{"comm":"app"},"runtime":{"containerId":"aaa","containerName":"web-1","containerImageName":"web:1"}}
{"type":"connect","dst":{"addr":"203.0.113.7","port":443,"version":4},"proc":{"comm":"x"},"runtime":{"containerId":"bbb","containerName":"other-1","containerImageName":"other:1"}}
`
	// No selector: unions everything (no ambiguity guard without --image/--container).
	all, err := aggregateEgress(strings.NewReader(nd), aggregateOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if all.EventCount != 4 {
		t.Errorf("event count = %d, want 4 (accept+close excluded)", all.EventCount)
	}
	if len(all.Dests) != 3 || len(all.PerReplica) != 2 {
		t.Errorf("union dests=%v replicas=%d, want 3 dests / 2 replicas", all.Dests, len(all.PerReplica))
	}
	// Sorted by address then port: 1.1.1.1 < 10.0.0.5 < 203.0.113.7 (byte order).
	wantOrder := []string{"1.1.1.1:443", "10.0.0.5:5432", "203.0.113.7:443"}
	for i, w := range wantOrder {
		if all.Dests[i].String() != w {
			t.Errorf("Dests[%d] = %q, want %q (sorted)", i, all.Dests[i].String(), w)
		}
	}

	// Target selection: only web-1's destinations; the duplicate 1.1.1.1:443
	// collapses to one dest but counts twice.
	sel, err := aggregateEgress(strings.NewReader(nd), aggregateOpts{Container: "web-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Dests) != 2 || len(sel.PerReplica) != 1 || sel.EventCount != 3 {
		t.Errorf("web-1: dests=%v replicas=%d events=%d, want 2/1/3", sel.Dests, len(sel.PerReplica), sel.EventCount)
	}
	if st := sel.Stats["1.1.1.1:443"]; st == nil || st.eventCount != 2 {
		t.Errorf("stats[1.1.1.1:443] = %+v, want eventCount 2", st)
	}
	if sel.Image != "web:1" {
		t.Errorf("image = %q, want web:1", sel.Image)
	}
}

func TestAggregateEgressImageAmbiguity(t *testing.T) {
	// --image matching >1 replica without --all-matching is an error, mirroring
	// the cap/fs/device aggregators.
	const nd = `
{"type":"connect","dst":{"addr":"1.1.1.1","port":443,"version":4},"proc":{"comm":"a"},"runtime":{"containerId":"aaa","containerName":"web-1","containerImageName":"web:1"}}
{"type":"connect","dst":{"addr":"2.2.2.2","port":443,"version":4},"proc":{"comm":"a"},"runtime":{"containerId":"bbb","containerName":"web-2","containerImageName":"web:1"}}
`
	if _, err := aggregateEgress(strings.NewReader(nd), aggregateOpts{Image: "web:1"}); err == nil {
		t.Fatal("expected ambiguous-selection error for >1 replica under --image")
	}
	obs, err := aggregateEgress(strings.NewReader(nd), aggregateOpts{Image: "web:1", AllMatching: true})
	if err != nil {
		t.Fatalf("--all-matching should union, got %v", err)
	}
	if len(obs.PerReplica) != 2 || len(obs.Dests) != 2 {
		t.Errorf("all-matching: dests=%v replicas=%d, want 2 dests / 2 replicas", obs.Dests, len(obs.PerReplica))
	}
}

func TestAggregateEgressMalformedHardFails(t *testing.T) {
	// A malformed NDJSON line is a hard error (deep-review L3 contract); a blank
	// line is skipped.
	const nd = `
{"type":"connect","dst":{"addr":"1.1.1.1","port":443,"version":4},"runtime":{"containerName":"web-1"}}

{bogus`
	if _, err := aggregateEgress(strings.NewReader(nd), aggregateOpts{}); err == nil {
		t.Fatal("expected hard error on malformed NDJSON line")
	}
}

func TestAggregateEgressFixture(t *testing.T) {
	f, err := os.Open("testdata/ig-versions/v0.51.0/trace_tcp_sample.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	obs, err := aggregateEgress(f, aggregateOpts{Container: "egress-target"})
	if err != nil {
		t.Fatal(err)
	}
	// egress-target dials 1.1.1.1:443 (twice) and 10.0.0.5:5432 (once); the
	// accept, the close, and the other-container connect are all excluded.
	if obs.EventCount != 3 || len(obs.Dests) != 2 {
		t.Fatalf("fixture: events=%d dests=%v, want 3 events / 2 dests", obs.EventCount, obs.Dests)
	}
	if obs.Dests[0].String() != "1.1.1.1:443" || obs.Dests[1].String() != "10.0.0.5:5432" {
		t.Errorf("fixture dests = %q, %q", obs.Dests[0], obs.Dests[1])
	}
}

func FuzzAggregateEgress(f *testing.F) {
	f.Add([]byte(`{"type":"connect","dst":{"addr":"1.1.1.1","port":443,"version":4},"runtime":{"containerName":"x"}}`))
	f.Add([]byte(`{"type":"accept","dst":{"addr":"","port":0}}`))
	f.Add([]byte("not json at all"))
	f.Add([]byte(`{"type":"connect","dst":{"addr":"::1","port":80,"version":6},"proc":{"comm":"c","pid":1}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Arbitrary NDJSON must never panic; a parse error is an acceptable
		// outcome (the hard-fail contract), a clean observation is the other.
		_, _ = aggregateEgress(bytes.NewReader(data), aggregateOpts{})
	})
}
