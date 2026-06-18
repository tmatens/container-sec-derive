package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

const egressFixture = "testdata/ig-versions/v0.51.0/trace_tcp_sample.ndjson"

func TestProduceEgressObservation_Fixture(t *testing.T) {
	s, err := produceEgressObservation(egressPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "egress-target"},
		Fixture:       egressFixture,
		Workload:      "/tmp/load.sh",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != "1.4" {
		t.Errorf("schema = %q, want 1.4", s.SchemaVersion)
	}
	if s.EgressRecommendation == nil || len(s.EgressRecommendation.Allowlist) != 2 {
		t.Fatalf("allowlist = %+v, want 2 destinations", s.EgressRecommendation)
	}
	if s.EgressRecommendation.Caveat != EgressCaveat {
		t.Errorf("recommendation caveat not the non-strippable EgressCaveat")
	}
	if len(s.EgressDestinations) != 2 || s.EgressDestinations[0].Addr != "1.1.1.1" || s.EgressDestinations[0].EventCount != 2 {
		t.Errorf("egress_destinations = %+v", s.EgressDestinations)
	}
	// Caps/fs/device scaffolding stays empty on an egress run.
	if len(s.Capabilities) != 0 || s.DeviceRecommendation != nil || s.FSRecommendation != nil {
		t.Error("non-egress observer blocks should be empty on an egress run")
	}
	// Workload present + clean trace → not forced low.
	if s.Confidence.Level == sidecar.ConfidenceLow {
		t.Errorf("confidence = %s with a workload + zero drops, want moderate; factors=%v", s.Confidence.Level, s.Confidence.Factors)
	}
}

func TestEgressSidecar_Golden(t *testing.T) {
	f, err := os.Open(egressFixture)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	eg, err := aggregateEgress(f, attrib.Opts{Container: "egress-target"})
	if err != nil {
		t.Fatal(err)
	}
	s := egressToSidecar(eg, attrib.Opts{Container: "egress-target"})
	s.ObservedAt = time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	s.DurationSeconds = 600
	s.Workload = "/tmp/load.sh"
	computeEgressConfidence(s)

	got, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "egress_sidecar_golden.json")
	if *updateGolden {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", goldenPath, len(got))
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update-golden to create)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("egress golden mismatch. Diff:\n--- want\n%s\n--- got\n%s", want, got)
	}
}

// TestObserveEgress_FakeIG covers the live spawn → parse → drop-accounting path:
// the fake ig streams trace_tcp events (a connect, an accept to be filtered, and
// a "lost N samples" stderr line); observeEgress must aggregate the outbound
// connect and surface the loss count on egressObservation.Dropped.
func TestObserveEgress_FakeIG(t *testing.T) {
	nd := strings.Join([]string{
		`{"type":"connect","dst":{"addr":"1.1.1.1","port":443,"version":4},"proc":{"comm":"app"},"runtime":{"containerId":"c1","containerName":"web","containerImageName":"web:1"}}`,
		`{"type":"accept","dst":{"addr":"10.9.9.9","port":33333,"version":4},"proc":{"comm":"app"},"runtime":{"containerId":"c1","containerName":"web","containerImageName":"web:1"}}`,
	}, "\n")
	ig := fakeIGRun(t, nd, "level=info msg=starting\nlost 4 samples\n")

	obs, err := observeEgress(context.Background(), ig, attrib.Opts{}, io.Discard)
	if err != nil {
		t.Fatalf("observeEgress: %v", err)
	}
	if obs.EventCount != 1 || len(obs.Dests) != 1 || obs.Dests[0].String() != "1.1.1.1:443" {
		t.Errorf("obs = events:%d dests:%v, want 1 connect / [1.1.1.1:443] (accept excluded)", obs.EventCount, obs.Dests)
	}
	if obs.Dropped != 4 {
		t.Errorf("Dropped = %d, want 4 (parsed from 'lost 4 samples')", obs.Dropped)
	}
}

func TestObserveEgress_IGMissing(t *testing.T) {
	_, err := observeEgress(context.Background(), "/nonexistent/csd-ig-egress-test", attrib.Opts{}, io.Discard)
	if err == nil {
		t.Fatal("expected missing-binary error")
	}
	if exit.CodeFor(err) != exit.IGMissing {
		t.Errorf("exit = %d, want exit.IGMissing (%d); err=%v", exit.CodeFor(err), exit.IGMissing, err)
	}
}

func TestComputeEgressConfidence(t *testing.T) {
	// No workload → forced low (inverted risk: an allowlist from idle traffic
	// will almost certainly be incomplete and will block real destinations).
	s := sidecar.NewSidecar()
	s.EgressDestinations = []sidecar.EgressDestination{{Addr: "1.1.1.1", Port: 443, EventCount: 2}}
	computeEgressConfidence(s)
	if s.Confidence.Level != sidecar.ConfidenceLow {
		t.Errorf("no-workload confidence = %s, want low; factors=%v", s.Confidence.Level, s.Confidence.Factors)
	}

	// Workload present, clean trace, single replica → moderate (capped while the
	// deferred preconditions stand).
	s2 := sidecar.NewSidecar()
	s2.Workload = "/tmp/load.sh"
	s2.EgressDestinations = []sidecar.EgressDestination{{Addr: "1.1.1.1", Port: 443, EventCount: 2}}
	computeEgressConfidence(s2)
	if s2.Confidence.Level != sidecar.ConfidenceModerate {
		t.Errorf("workload confidence = %s, want moderate; factors=%v", s2.Confidence.Level, s2.Confidence.Factors)
	}
}

// TestRunEgress_FormatGuard: the egress observer accepts --format json end to
// end and rejects the compose-security formats with EX_USAGE (the nft/k8s
// emitters are a follow-on).
func TestRunEgress_FormatGuard(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{
		"--observe", "egress", "--container", "egress-target",
		"--fixture", egressFixture, "--format", "json",
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("egress --format json: %v", err)
	}
	var s sidecar.Sidecar
	if jerr := json.Unmarshal(out.Bytes(), &s); jerr != nil {
		t.Fatalf("stdout is not valid sidecar JSON: %v", jerr)
	}
	if s.EgressRecommendation == nil || len(s.EgressRecommendation.Allowlist) != 2 {
		t.Errorf("run() egress allowlist = %+v, want 2", s.EgressRecommendation)
	}

	var o2, e2 bytes.Buffer
	err = run([]string{
		"--observe", "egress", "--container", "egress-target",
		"--fixture", egressFixture, "--format", "compose",
	}, &o2, &e2)
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("egress --format compose: exit = %d, want exit.Usage (%d)", exit.CodeFor(err), exit.Usage)
	}
}
