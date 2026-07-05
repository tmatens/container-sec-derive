package sidecar

import "testing"

func TestCurrentSchemaMajorMatchesConstant(t *testing.T) {
	// The compatibility boundary must track SchemaVersion. If SchemaVersion ever
	// gains a new major, this stays correct with no edit here (that is the point).
	m, ok := schemaMajor(SchemaVersion)
	if !ok {
		t.Fatalf("SchemaVersion %q does not parse a major", SchemaVersion)
	}
	if got := CurrentSchemaMajor(); got != m {
		t.Errorf("CurrentSchemaMajor() = %d, want %d (from SchemaVersion %q)", got, m, SchemaVersion)
	}
}

func TestSchemaMajorCompatible(t *testing.T) {
	cur := CurrentSchemaMajor()
	cases := []struct {
		version string
		want    bool
	}{
		{SchemaVersion, true}, // the exact current version
		{"1.0", cur == 1},     // any minor within the current major
		{"1.99", cur == 1},
		{"1", cur == 1}, // bare major
		{"2.0", cur == 2},
		{"0.9", cur == 0},
		{"", false},         // missing
		{"garbage", false},  // unparseable
		{"v1.5", false},     // leading non-digit
		{"1.5.0", cur == 1}, // extra component is ignored past the major
		{"-1.0", false},     // negative major
	}
	for _, c := range cases {
		if got := SchemaMajorCompatible(c.version); got != c.want {
			t.Errorf("SchemaMajorCompatible(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}
