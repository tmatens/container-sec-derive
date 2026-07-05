package observe

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestEmitAdvisoryWarnings_ZeroEvents(t *testing.T) {
	cases := []struct {
		name      string
		live      bool
		recorded  int
		container string
		image     string
		wantWarn  bool
		wantText  string
	}{
		{"live zero events, container selector", true, 0, "app", "", true, `--container "app"`},
		{"live zero events, image selector", true, 0, "", "postgres:16", true, `--image "postgres:16"`},
		{"live zero events, no selector", true, 0, "", "", true, "the target container"},
		{"fixture zero events is exempt", false, 0, "app", "", false, ""},
		{"live with events does not warn", true, 5, "app", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &sidecar.Sidecar{}
			s.TraceHealth.EventsRecorded = tc.recorded
			var buf bytes.Buffer
			EmitAdvisoryWarnings(s, &buf, tc.live, tc.container, tc.image)
			got := buf.String()
			has := strings.Contains(got, "0 events recorded")
			if has != tc.wantWarn {
				t.Fatalf("zero-events warning present = %v, want %v (stderr: %q)", has, tc.wantWarn, got)
			}
			if tc.wantWarn && !strings.Contains(got, tc.wantText) {
				t.Errorf("warning should name the selector %q, got: %q", tc.wantText, got)
			}
		})
	}
}

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

func TestConfidenceBuilder(t *testing.T) {
	var c ConfidenceBuilder
	c.Info("all good")
	c.Moderate("one caveat")
	c.Low("hard problem")
	c.Moderate("another caveat")

	want := []string{"ok: all good", "moderate: one caveat", "low: hard problem", "moderate: another caveat"}
	if len(c.Factors) != len(want) {
		t.Fatalf("Factors = %v, want %v", c.Factors, want)
	}
	for i := range want {
		if c.Factors[i] != want[i] {
			t.Errorf("Factors[%d] = %q, want %q", i, c.Factors[i], want[i])
		}
	}
	if c.ModerateHits != 2 {
		t.Errorf("ModerateHits = %d, want 2", c.ModerateHits)
	}
	if !c.ForceLow {
		t.Error("ForceLow = false, want true after a Low")
	}
}

func TestConfidenceBuilderAddDropRateFactors(t *testing.T) {
	cases := []struct {
		name     string
		rate     float64
		want     string // "" = no factor
		forceLow bool
		modHits  int
	}{
		{"zero adds nothing", 0, "", false, 0},
		{"sub-1% is moderate", 0.005, "moderate: drop rate 0.0050 > 0 but < 1%", false, 1},
		{"exactly 1% is low", 0.01, "low: drop rate 0.0100 >= 1%", true, 0},
		{"above 1% is low", 0.2, "low: drop rate 0.2000 >= 1%", true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c ConfidenceBuilder
			c.AddDropRateFactors(tc.rate)
			if tc.want == "" {
				if len(c.Factors) != 0 {
					t.Fatalf("Factors = %v, want none", c.Factors)
				}
				return
			}
			if len(c.Factors) != 1 || c.Factors[0] != tc.want {
				t.Fatalf("Factors = %v, want [%q]", c.Factors, tc.want)
			}
			if c.ForceLow != tc.forceLow || c.ModerateHits != tc.modHits {
				t.Errorf("ForceLow=%v ModerateHits=%d, want %v/%d", c.ForceLow, c.ModerateHits, tc.forceLow, tc.modHits)
			}
		})
	}
}

func TestIterateNDJSON(t *testing.T) {
	t.Run("skips empty lines and passes the rest", func(t *testing.T) {
		in := "a\n\nb\n\nc\n"
		var got []string
		if err := IterateNDJSON(strings.NewReader(in), func(line []byte) error {
			got = append(got, string(line))
			return nil
		}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Join(got, ",") != "a,b,c" {
			t.Errorf("got %v, want [a b c]", got)
		}
	})

	t.Run("returns fn error and stops", func(t *testing.T) {
		sentinel := errors.New("boom")
		count := 0
		err := IterateNDJSON(strings.NewReader("a\nb\nc\n"), func(line []byte) error {
			count++
			if string(line) == "b" {
				return sentinel
			}
			return nil
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("err = %v, want sentinel", err)
		}
		if count != 2 {
			t.Errorf("fn called %d times, want 2 (stopped at b)", count)
		}
	})

	t.Run("over-long line surfaces as a scanner error", func(t *testing.T) {
		huge := strings.Repeat("x", MaxScanLineBytes+1)
		called := false
		err := IterateNDJSON(strings.NewReader(huge+"\n"), func(line []byte) error {
			called = true
			return nil
		})
		if err == nil {
			t.Fatal("want a scanner error for an over-long line, got nil")
		}
		if called {
			t.Error("fn should not be called for a line exceeding MaxScanLineBytes")
		}
	})
}
