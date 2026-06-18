package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
)

func TestFileEventUnmarshal(t *testing.T) {
	line := `{"timestamp":1700000000002,"syscall":"openat","flags":"O_WRONLY|O_CREAT","flags_raw":65,"fname":"/var/run/x.lock","fpath":"/var/run/x.lock","mode":420,"error_raw":0,"proc":{"comm":"postgres","pid":4010},"runtime":{"runtimeName":"docker","containerId":"abc123","containerName":"postgres-1","containerImageName":"postgres:16"}}`
	var e fileEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Timestamp != 1700000000002 {
		t.Errorf("timestamp = %d", e.Timestamp)
	}
	if e.Syscall != "openat" || !e.HasFlagsRaw || e.FlagsRaw != 65 {
		t.Errorf("syscall/flags = %q / %v / %d", e.Syscall, e.HasFlagsRaw, e.FlagsRaw)
	}
	if e.Path() != "/var/run/x.lock" {
		t.Errorf("path = %q", e.Path())
	}
	if e.Runtime.ContainerName != "postgres-1" || e.Proc.Comm != "postgres" {
		t.Errorf("envelope = %+v / %+v", e.Runtime, e.Proc)
	}
}

func TestFileEventTimestampRawNanos(t *testing.T) {
	// Live ig emits nanoseconds in timestamp_raw; UnmarshalJSON converts to ms.
	var e fileEvent
	if err := json.Unmarshal([]byte(`{"timestamp_raw":1700000000002000000,"syscall":"openat"}`), &e); err != nil {
		t.Fatal(err)
	}
	if e.Timestamp != 1700000000002 {
		t.Errorf("ns→ms = %d, want 1700000000002", e.Timestamp)
	}
}

func TestFileEventIsWrite(t *testing.T) {
	cases := []struct {
		name     string
		flagsRaw int64
		hasRaw   bool
		flags    string
		want     bool
	}{
		{"rdonly", oRdOnly, true, "O_RDONLY", false},
		{"wronly", oWrOnly, true, "O_WRONLY", true},
		{"rdwr", oRdWr, true, "O_RDWR", true},
		{"wronly+creat", oWrOnly | oCreat, true, "O_WRONLY|O_CREAT", true},
		{"rdwr+creat", oRdWr | oCreat, true, "O_RDWR|O_CREAT", true},
		{"wronly+append", oWrOnly | oAppend, true, "O_WRONLY|O_APPEND", true},
		{"rdonly+creat", oRdOnly | oCreat, true, "O_RDONLY|O_CREAT", true}, // creates a file
		{"rdonly+trunc-bit", oRdOnly | oTrunc, true, "", true},
		// flags_raw absent → fall back to the decoded string.
		{"string-wronly", 0, false, "O_WRONLY|O_CREAT", true},
		{"string-rdonly", 0, false, "O_RDONLY", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := fileEvent{FlagsRaw: c.flagsRaw, HasFlagsRaw: c.hasRaw, Flags: c.flags}
			if got := e.IsWrite(); got != c.want {
				t.Errorf("IsWrite(flags_raw=%d hasRaw=%v flags=%q) = %v, want %v",
					c.flagsRaw, c.hasRaw, c.flags, got, c.want)
			}
		})
	}
}

func TestFileEventPathFallback(t *testing.T) {
	// fpath wins; fname is the fallback when ig ran without --paths.
	if (fileEvent{Fname: "/a", Fpath: "/resolved/a"}).Path() != "/resolved/a" {
		t.Error("fpath should win")
	}
	if (fileEvent{Fname: "/a"}).Path() != "/a" {
		t.Error("fname fallback")
	}
}

func TestAggregateWrites(t *testing.T) {
	// Two replicas; one read-only open (/etc/hosts) that must be excluded.
	const nd = `
{"syscall":"openat","flags_raw":65,"fpath":"/var/cache/a","proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"web-1","containerImageName":"web:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"/var/run/a.pid","proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"web-1","containerImageName":"web:1"}}
{"syscall":"openat","flags_raw":0,"fpath":"/etc/hosts","proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"web-1","containerImageName":"web:1"}}
{"syscall":"openat","flags_raw":66,"fpath":"/data/db","proc":{"comm":"db"},"runtime":{"containerId":"bbb222bbb222","containerName":"db-1","containerImageName":"db:1"}}
`
	obs, err := aggregateWrites(strings.NewReader(nd), attrib.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if obs.EventCount != 3 {
		t.Errorf("event count = %d, want 3", obs.EventCount)
	}
	if len(obs.PerReplica) != 2 {
		t.Errorf("replicas = %d, want 2", len(obs.PerReplica))
	}
	want := []string{"/data/db", "/var/cache/a", "/var/run/a.pid"}
	if len(obs.Paths) != len(want) {
		t.Fatalf("union paths = %v, want %v", obs.Paths, want)
	}
	for i, p := range want {
		if obs.Paths[i] != p {
			t.Errorf("Paths[%d] = %q, want %q (should be sorted)", i, obs.Paths[i], p)
		}
	}

	// Target selection: only web-1's writes.
	sel, err := aggregateWrites(strings.NewReader(nd), attrib.Opts{Container: "web-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Paths) != 2 || len(sel.PerReplica) != 1 {
		t.Errorf("selected web-1: paths=%v replicas=%d, want 2 paths / 1 replica", sel.Paths, len(sel.PerReplica))
	}
}

// TestTraceOpenFixtureWritePaths is the end-to-end parse check for the v0.2
// observer's signal: filtering the committed trace_open fixture to write-intent
// opens must yield exactly the writable paths (read-only opens excluded).
func TestTraceOpenFixtureWritePaths(t *testing.T) {
	f, err := os.Open("testdata/ig-versions/v0.51.0/trace_open_sample.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var writes []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e fileEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("fixture line: %v\n%s", err, line)
		}
		if e.IsWrite() {
			writes = append(writes, e.Path())
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"/var/run/postgresql/.s.PGSQL.5432.lock": true,
		"/var/lib/postgresql/data/base/1/1259":   true,
		"/var/log/postgresql/postgresql.log":     true,
	}
	if len(writes) != len(want) {
		t.Fatalf("got %d write paths %v, want %d", len(writes), writes, len(want))
	}
	for _, p := range writes {
		if !want[p] {
			t.Errorf("unexpected write path %q (read-only opens should be filtered)", p)
		}
	}
}
