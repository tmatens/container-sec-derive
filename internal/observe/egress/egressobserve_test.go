package egress

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
	"github.com/tmatens/container-sec-derive/internal/obstest"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

const egressFixture = "../../../testdata/ig-versions/v0.51.0/trace_tcp_sample.ndjson"
const dnsFixture = "../../../testdata/ig-versions/v0.51.0/trace_dns_sample.ndjson"

func TestProduceEgressObservation_Fixture(t *testing.T) {
	s, err := ProduceEgressObservation(EgressPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "egress-target"},
		Fixture:       egressFixture,
		Workload:      "/tmp/load.sh",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != "1.5" {
		t.Errorf("schema = %q, want 1.5", s.SchemaVersion)
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
	s := egressToSidecar(eg, nil, attrib.Opts{Container: "egress-target"})
	s.ObservedAt = time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	s.DurationSeconds = 600
	s.Workload = "/tmp/load.sh"
	computeEgressConfidence(s)

	got, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("..", "..", "..", "testdata", "egress_sidecar_golden.json")
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

// TestProduceEgressObservation_DNSEnriched runs the full fixture pipeline with
// both the trace_tcp fixture and the trace_dns fixture (#159): the egress
// destinations must gain the hostnames that resolved to them, and the
// recommendation must carry the DNS resolver endpoint. The trace_dns sample is
// consistent with the trace_tcp sample (1.1.1.1 <- api.example.com, 10.0.0.5 <-
// db.internal, resolver 10.0.0.2:53).
func TestProduceEgressObservation_DNSEnriched(t *testing.T) {
	s, err := ProduceEgressObservation(EgressPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "egress-target"},
		Fixture:       egressFixture,
		DNSFixture:    dnsFixture,
		Workload:      "/tmp/load.sh",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	// Hostnames annotate the IP destinations.
	byAddr := map[string][]string{}
	for _, d := range s.EgressDestinations {
		byAddr[d.Addr] = d.Hostnames
	}
	if got := byAddr["1.1.1.1"]; len(got) != 1 || got[0] != "api.example.com" {
		t.Errorf("1.1.1.1 hostnames = %v, want [api.example.com]", got)
	}
	if got := byAddr["10.0.0.5"]; len(got) != 1 || got[0] != "db.internal" {
		t.Errorf("10.0.0.5 hostnames = %v, want [db.internal]", got)
	}
	// The resolver is in the recommendation, kept separate from the TCP allowlist.
	if s.EgressRecommendation == nil || len(s.EgressRecommendation.Resolvers) != 1 {
		t.Fatalf("dns_resolvers = %+v, want one", s.EgressRecommendation)
	}
	if r := s.EgressRecommendation.Resolvers[0]; r.Addr != "10.0.0.2" || r.Port != 53 {
		t.Errorf("resolver = %+v, want 10.0.0.2:53", r)
	}
}

// TestEgressDNSSidecar_Golden golden-checks the full DNS-enriched sidecar.
func TestEgressDNSSidecar_Golden(t *testing.T) {
	s, err := ProduceEgressObservation(EgressPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "egress-target"},
		Fixture:       egressFixture,
		DNSFixture:    dnsFixture,
		Workload:      "/tmp/load.sh",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	s.ObservedAt = time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	s.DurationSeconds = 600

	got, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("..", "..", "..", "testdata", "egress_dns_sidecar_golden.json")
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
		t.Errorf("egress dns golden mismatch. Diff:\n--- want\n%s\n--- got\n%s", want, got)
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
	ig := obstest.FakeIGRun(t, nd, "level=info msg=starting\nlost 4 samples\n")

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

func TestObserveDNS_FakeIG(t *testing.T) {
	// The live trace_dns path: a query + its response + a drop line. observeDNS
	// must build the IP->hostname map, record the resolver, and surface drops.
	nd := strings.Join([]string{
		`{"qr":"Q","qr_raw":false,"name":"api.example.com.","id":1,"dst":{"addr":"10.0.0.2","port":53,"version":4},"runtime":{"containerName":"web"}}`,
		`{"qr":"R","qr_raw":true,"name":"api.example.com.","addresses":"1.1.1.1","id":1,"src":{"addr":"10.0.0.2","port":53,"version":4},"runtime":{"containerName":"web"}}`,
	}, "\n")
	fakeIG := obstest.FakeIGRun(t, nd, "level=info msg=starting\nlost 2 samples\n")

	corr, err := observeDNS(context.Background(), fakeIG, attrib.Opts{}, io.Discard)
	if err != nil {
		t.Fatalf("observeDNS: %v", err)
	}
	if got := corr.HostnamesFor("1.1.1.1"); len(got) != 1 || got[0] != "api.example.com" {
		t.Errorf("1.1.1.1 -> %v, want [api.example.com]", got)
	}
	if len(corr.Resolvers) != 1 || corr.Resolvers[0].Addr != "10.0.0.2" || corr.Resolvers[0].Port != 53 {
		t.Errorf("Resolvers = %+v, want one 10.0.0.2:53", corr.Resolvers)
	}
	if corr.Dropped != 2 {
		t.Errorf("Dropped = %d, want 2", corr.Dropped)
	}
}

func TestObserveDNS_IGMissing(t *testing.T) {
	_, err := observeDNS(context.Background(), "/nonexistent/csd-ig-dns-test", attrib.Opts{}, io.Discard)
	if err == nil {
		t.Fatal("expected missing-binary error")
	}
	if exit.CodeFor(err) != exit.IGMissing {
		t.Errorf("exit = %d, want exit.IGMissing (%d); err=%v", exit.CodeFor(err), exit.IGMissing, err)
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
