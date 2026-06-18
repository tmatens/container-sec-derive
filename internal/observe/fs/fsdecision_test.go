package fs

import (
	"reflect"
	"testing"
)

func TestCorrelateWrites(t *testing.T) {
	// postgres-shaped: data dir is a volume; lock + log are rootfs writes.
	writes := []string{
		"/var/lib/postgresql/data/base/1/1259",
		"/var/log/postgresql/postgresql.log",
		"/var/run/postgresql/.s.PGSQL.5432.lock",
	}
	mounts := []string{"/var/lib/postgresql/data"}

	rec := correlateWrites(writes, mounts)
	if !rec.ReadOnly {
		t.Error("ReadOnly = false, want true")
	}
	wantTmpfs := []string{"/var/log/postgresql", "/var/run/postgresql"}
	if !reflect.DeepEqual(rec.TmpfsPaths, wantTmpfs) {
		t.Errorf("TmpfsPaths = %v, want %v", rec.TmpfsPaths, wantTmpfs)
	}
	wantCovered := []string{"/var/lib/postgresql/data/base/1/1259"}
	if !reflect.DeepEqual(rec.VolumeCovered, wantCovered) {
		t.Errorf("VolumeCovered = %v, want %v", rec.VolumeCovered, wantCovered)
	}
}

func TestCorrelateWritesAllVolumeCovered(t *testing.T) {
	writes := []string{"/data/a", "/data/sub/b"}
	rec := correlateWrites(writes, []string{"/data"})
	if !rec.ReadOnly {
		t.Error("ReadOnly = false, want true")
	}
	if len(rec.TmpfsPaths) != 0 {
		t.Errorf("TmpfsPaths = %v, want empty (all writes under the volume)", rec.TmpfsPaths)
	}
	if len(rec.VolumeCovered) != 2 {
		t.Errorf("VolumeCovered = %v, want 2", rec.VolumeCovered)
	}
}

func TestCorrelateWritesNoMounts(t *testing.T) {
	writes := []string{"/tmp/x/a", "/tmp/x/b", "/var/cache/c"}
	rec := correlateWrites(writes, nil)
	want := []string{"/tmp/x", "/var/cache"} // /tmp/x/a and /tmp/x/b share a parent
	if !reflect.DeepEqual(rec.TmpfsPaths, want) {
		t.Errorf("TmpfsPaths = %v, want %v", rec.TmpfsPaths, want)
	}
	if len(rec.VolumeCovered) != 0 {
		t.Errorf("VolumeCovered = %v, want empty", rec.VolumeCovered)
	}
}

func TestUnderAnyMount(t *testing.T) {
	mounts := []string{"/data", "/var/lib/app/"}
	cases := []struct {
		p    string
		want bool
	}{
		{"/data", true},     // exact
		{"/data/x/y", true}, // below
		{"/data2", false},   // sibling prefix, NOT under /data
		{"/var/lib/app/cache", true},
		{"/var/lib/application", false}, // prefix of the trimmed mount, but not under it
		{"/etc/passwd", false},
	}
	for _, c := range cases {
		if got := underAnyMount(c.p, mounts); got != c.want {
			t.Errorf("underAnyMount(%q) = %v, want %v", c.p, got, c.want)
		}
	}
}

func TestCollapseToAncestors(t *testing.T) {
	// Sorted input (as sortedKeys produces): ancestors precede descendants.
	in := []string{"/var/cache", "/var/log", "/var/log/app", "/var/log/app/sub"}
	want := []string{"/var/cache", "/var/log"}
	if got := collapseToAncestors(in); !reflect.DeepEqual(got, want) {
		t.Errorf("collapseToAncestors(%v) = %v, want %v", in, got, want)
	}
	// Sibling dirs sharing a prefix segment must NOT collapse.
	in2 := []string{"/var/log", "/var/log2"}
	if got := collapseToAncestors(in2); !reflect.DeepEqual(got, in2) {
		t.Errorf("collapseToAncestors(%v) = %v, want unchanged", in2, got)
	}
}
