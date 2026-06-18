package fs

import (
	"errors"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
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
	_, err := aggregateWrites(strings.NewReader(twoReplicaWrites), attrib.Opts{Image: "web:1"})
	var amb *exit.AmbiguousSelectionError
	if !errors.As(err, &amb) {
		t.Fatalf("err = %v, want exit.AmbiguousSelectionError", err)
	}
	if len(amb.Replicas()) != 2 {
		t.Errorf("ambiguity listed %d replicas, want 2", len(amb.Replicas()))
	}
}

// --all-matching unions the write paths and records the cross-replica
// disagreement, which then pulls confidence down.
func TestProduceFSObservation_AllMatchingDisagreement(t *testing.T) {
	writes, err := aggregateWrites(strings.NewReader(twoReplicaWrites), attrib.Opts{Image: "web:1", AllMatching: true})
	if err != nil {
		t.Fatal(err)
	}
	s := fsToSidecar(writes, nil, attrib.Opts{Image: "web:1", AllMatching: true})
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
	if s.Confidence.Level != sidecar.ConfidenceLow {
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

// run() surfaces the ambiguity as exit.TargetAmbiguous (40).
