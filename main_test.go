package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestAggregate_DistinctCapsSorted(t *testing.T) {
	input := `{"capName":"CAP_CHOWN","container":{"id":"abc123def456","name":"pg"}}
{"capName":"CAP_SETUID","container":{"id":"abc123def456","name":"pg"}}
{"capName":"CAP_CHOWN","container":{"id":"abc123def456","name":"pg"}}
{"capName":"CAP_DAC_OVERRIDE","container":{"id":"abc123def456","name":"pg"}}
`
	s, err := aggregate(strings.NewReader(input), "pg")
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	want := []string{"CHOWN", "DAC_OVERRIDE", "SETUID"}
	if !equalSlice(s.CapNames(), want) {
		t.Errorf("caps = %v, want %v", s.CapNames(), want)
	}
}

func TestAggregate_FiltersByContainer(t *testing.T) {
	input := `{"capName":"CAP_CHOWN","container":{"id":"aaa","name":"pg"}}
{"capName":"CAP_NET_RAW","container":{"id":"bbb","name":"other"}}
`
	s, err := aggregate(strings.NewReader(input), "pg")
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN"}) {
		t.Errorf("expected only CHOWN for pg, got %v", s.CapNames())
	}
}

func TestAggregate_ContainerIDPrefix(t *testing.T) {
	input := `{"capName":"CAP_SETGID","container":{"id":"abcdef1234567890","name":""}}` + "\n"
	s, err := aggregate(strings.NewReader(input), "abcdef")
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"SETGID"}) {
		t.Errorf("prefix match failed, got %v", s.CapNames())
	}
}

func TestAggregate_EmptyTargetMatchesAll(t *testing.T) {
	input := `{"capName":"CAP_CHOWN","container":{"id":"a"}}
{"capName":"CAP_SETUID","container":{"id":"b"}}
`
	s, err := aggregate(strings.NewReader(input), "")
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN", "SETUID"}) {
		t.Errorf("got %v", s.CapNames())
	}
}

func TestAggregate_SkipsMalformedLines(t *testing.T) {
	input := "not json at all\n" +
		`{"capName":"CAP_CHOWN","container":{"id":"a"}}` + "\n" +
		"\n" + // blank line
		`{"capName":"CAP_SETUID","container":{"id":"a"}}` + "\n"
	s, err := aggregate(strings.NewReader(input), "a")
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !equalSlice(s.CapNames(), []string{"CHOWN", "SETUID"}) {
		t.Errorf("got %v", s.CapNames())
	}
}

func TestRun_FixtureMode(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{"--fixture", "testdata/sample.ndjson", "--container", "postgres-1"}, &out, &errBuf)
	if err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errBuf.String())
	}
	// Expected caps from the sample fixture, matching compose-lint's
	// curated postgres profile (PLAN.md §v1 success criteria).
	want := "CHOWN\nDAC_OVERRIDE\nFOWNER\nSETGID\nSETUID\n"
	if out.String() != want {
		t.Errorf("output mismatch:\ngot:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestRun_RequiresContainerOrFixture(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := run([]string{}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected error when neither --container nor --fixture given")
	}
}

func TestMain_FixtureExists(t *testing.T) {
	// Sanity: fixture referenced by TestRun_FixtureMode must exist.
	if _, err := os.Stat("testdata/sample.ndjson"); err != nil {
		t.Fatalf("testdata/sample.ndjson missing: %v", err)
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
