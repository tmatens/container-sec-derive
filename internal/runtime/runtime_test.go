package runtime

import "testing"

func TestResolve(t *testing.T) {
	for _, c := range []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "docker", false}, // default
		{"docker", "docker", false},
		{"podman", "podman", false},
		{"containerd", "", true},      // not a CLI we support
		{"DOCKER", "", true},          // case-sensitive
		{"/usr/bin/docker", "", true}, // not a passthrough path
	} {
		got, err := Resolve(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Resolve(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("Resolve(%q) = %q, %v; want %q, nil", c.in, got, err, c.want)
		}
	}
}
