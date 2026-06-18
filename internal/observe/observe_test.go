package observe

import "testing"

func TestLooksLikeWSL2(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"native linux 6.x", "Linux version 6.17.0-20-generic (buildd@lcy02-amd64-001) (gcc ...) #20-Ubuntu SMP", false},
		{"empty", "", false},
		// WSL2 5.10 / 5.15 build banner.
		{"microsoft-standard-WSL2", "Linux version 5.15.146.1-microsoft-standard-WSL2 (root@build) (gcc ...) #1 SMP", true},
		// Older WSL2 5.10 banner that omits the explicit WSL2 token.
		{"microsoft-standard only", "Linux version 5.10.16.3-microsoft-standard (oe-user@oe-host) (gcc ...) #1 SMP", true},
		// Mixed-case sanity (banners have been lower-case to date but we
		// fold for safety).
		{"uppercase token", "Linux version 5.15.0-MICROSOFT-STANDARD-WSL2", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeWSL2(tc.in); got != tc.want {
				t.Errorf("looksLikeWSL2(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
