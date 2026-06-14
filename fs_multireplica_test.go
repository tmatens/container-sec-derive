package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two replicas of web:1. Both write /var/log/app.log; only web-1 writes
// /var/cache/x — so /var/cache/x is the cross-replica disagreement.
const twoReplicaWrites = `
{"syscall":"openat","flags_raw":1,"fpath":"/var/log/app.log","proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"web-1","containerImageName":"web:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"/var/cache/x","proc":{"comm":"app"},"runtime":{"containerId":"aaa111aaa111","containerName":"web-1","containerImageName":"web:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"/var/log/app.log","proc":{"comm":"app"},"runtime":{"containerId":"bbb222bbb222","containerName":"web-2","containerImageName":"web:1"}}
`

// --image matching >1 replica without --all-matching is ambiguous (caps parity).
func TestAggregateWrites_AmbiguousImage(t *testing.T) {
	_, err := aggregateWrites(strings.NewReader(twoReplicaWrites), aggregateOpts{Image: "web:1"})
	var amb *ambiguousSelectionError
	if !errors.As(err, &amb) {
		t.Fatalf("err = %v, want ambiguousSelectionError", err)
	}
	if len(amb.replicas) != 2 {
		t.Errorf("ambiguity listed %d replicas, want 2", len(amb.replicas))
	}
}

// --all-matching unions the write paths and records the cross-replica
// disagreement, which then pulls confidence down.
func TestProduceFSObservation_AllMatchingDisagreement(t *testing.T) {
	writes, err := aggregateWrites(strings.NewReader(twoReplicaWrites), aggregateOpts{Image: "web:1", AllMatching: true})
	if err != nil {
		t.Fatal(err)
	}
	s := fsToSidecar(writes, nil, aggregateOpts{Image: "web:1", AllMatching: true})
	if s.Target.ReplicasObserved != 2 {
		t.Errorf("replicas = %d, want 2", s.Target.ReplicasObserved)
	}
	want := []string{"/var/cache/x"}
	if strings.Join(s.Target.ReplicaWritePathDisagreement, ",") != strings.Join(want, ",") {
		t.Errorf("disagreement = %v, want %v", s.Target.ReplicaWritePathDisagreement, want)
	}
	// Union recommendation covers both paths' parents as tmpfs candidates.
	if len(s.FSRecommendation.TmpfsPaths) != 2 {
		t.Errorf("tmpfs = %v, want 2 (/var/cache, /var/log)", s.FSRecommendation.TmpfsPaths)
	}
	computeFSConfidence(s)
	// disagreement spans 1 path → moderate hit; no workload → moderate hit;
	// two moderates force low.
	if s.Confidence.Level != ConfidenceLow {
		t.Errorf("confidence = %q, want low (disagreement + no workload)", s.Confidence.Level)
	}
	found := false
	for _, f := range s.Confidence.Factors {
		if strings.Contains(f, "replica write-path disagreement") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a replica write-path disagreement factor, got %v", s.Confidence.Factors)
	}
}

// run() surfaces the ambiguity as ExitTargetAmbiguous (40).
func TestRun_ObserveFSAmbiguousImage(t *testing.T) {
	dir := t.TempDir()
	fix := filepath.Join(dir, "two.ndjson")
	if err := os.WriteFile(fix, []byte(twoReplicaWrites), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	err := run([]string{"--observe", "fs", "--fixture", fix, "--image", "web:1"}, &out, &errBuf)
	if exitCodeFor(err) != ExitTargetAmbiguous {
		t.Errorf("exit code = %d, want %d (ambiguous)", exitCodeFor(err), ExitTargetAmbiguous)
	}

	// With --all-matching the same fixture succeeds.
	out.Reset()
	errBuf.Reset()
	if err := run([]string{"--observe", "fs", "--fixture", fix, "--image", "web:1", "--all-matching"}, &out, &errBuf); err != nil {
		t.Fatalf("--all-matching run: %v (stderr: %s)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), "read_only: true") {
		t.Errorf("all-matching output unexpected:\n%s", out.String())
	}
}
