package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestIGProvenancePredicate runs scripts/gen-ig-provenance.sh and asserts the
// emitted predicate is valid JSON whose contents agree with the committed pin
// (main.go PinnedIGVersion and ig-pin/SHA256SUMS). This is the PR-time gate for
// the ig-provenance attestation; the cosign attest call itself runs only at a
// release tag (release.yml), but the predicate is deterministic and checkable
// here without Docker/cosign.
func TestIGProvenancePredicate(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	out, err := exec.Command("bash", "scripts/gen-ig-provenance.sh").Output()
	if err != nil {
		t.Fatalf("gen-ig-provenance.sh failed: %v", err)
	}

	var p struct {
		Component string `json:"component"`
		Version   string `json:"version"`
		Source    string `json:"source"`
		Artifacts []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"artifacts"`
		Verification struct {
			CosignVerified  bool   `json:"cosignVerified"`
			PublicKey       string `json:"publicKey"`
			PublicKeySHA256 string `json:"publicKeySha256"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatalf("predicate is not valid JSON: %v\n%s", err, out)
	}

	if p.Component != "inspektor-gadget" {
		t.Errorf("component = %q, want inspektor-gadget", p.Component)
	}
	if p.Version != PinnedIGVersion {
		t.Errorf("version = %q, want PinnedIGVersion %q", p.Version, PinnedIGVersion)
	}
	if !strings.HasSuffix(p.Source, PinnedIGVersion) {
		t.Errorf("source %q does not end in PinnedIGVersion %q", p.Source, PinnedIGVersion)
	}
	if !p.Verification.CosignVerified {
		t.Error("verification.cosignVerified = false, want true")
	}

	// Cross-check each artifact digest against ig-pin/SHA256SUMS.
	sums := pinDigests(t)
	if len(p.Artifacts) != 2 {
		t.Fatalf("got %d artifacts, want 2 (amd64, arm64)", len(p.Artifacts))
	}
	for _, a := range p.Artifacts {
		want, ok := sums[a.Name]
		if !ok {
			t.Errorf("artifact %q not present in ig-pin/SHA256SUMS", a.Name)
			continue
		}
		if a.SHA256 != want {
			t.Errorf("artifact %q sha256 = %s, pin has %s", a.Name, a.SHA256, want)
		}
	}

	// Cross-check the recorded public-key fingerprint.
	keyBytes, err := os.ReadFile(p.Verification.PublicKey)
	if err != nil {
		t.Fatalf("reading %s: %v", p.Verification.PublicKey, err)
	}
	sum := sha256.Sum256(keyBytes)
	if got := hex.EncodeToString(sum[:]); got != p.Verification.PublicKeySHA256 {
		t.Errorf("publicKeySha256 = %s, computed %s", p.Verification.PublicKeySHA256, got)
	}
}

// pinDigests parses ig-pin/SHA256SUMS into filename -> sha256.
func pinDigests(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("ig-pin/SHA256SUMS")
	if err != nil {
		t.Fatalf("reading ig-pin/SHA256SUMS: %v", err)
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			m[f[1]] = f[0]
		}
	}
	return m
}
