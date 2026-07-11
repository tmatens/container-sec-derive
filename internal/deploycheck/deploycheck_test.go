package deploycheck

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
)

// stubEnv writes a fake compose_derive.sh that prints stdoutBody to stdout,
// stderrBody to stderr, and exits with code -- so the wrapper's flag handling,
// evidence passthrough, and exit-code mapping are testable with no docker, no
// ig, and no python. Returns (scriptDir, composePath) to feed RunDeployCheck.
func stubEnv(t *testing.T, stdoutBody, stderrBody string, code int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/usr/bin/env bash\n"
	if stdoutBody != "" {
		script += "cat <<'JSON'\n" + stdoutBody + "\nJSON\n"
	}
	if stderrBody != "" {
		script += "echo " + shellQuote(stderrBody) + " >&2\n"
	}
	script += "exit " + itoa(code) + "\n"
	if err := os.WriteFile(filepath.Join(dir, deriveScript), []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	compose := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(compose, []byte("services:\n  svc: {}\n"), 0o644); err != nil {
		t.Fatalf("write compose: %v", err)
	}
	return dir, compose
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func run(t *testing.T, scriptDir, compose string, extra ...string) (string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	args := append([]string{"--compose", compose, "--service", "svc", "--script-dir", scriptDir}, extra...)
	err := RunDeployCheck(args, &out, &errb)
	return out.String(), errb.String(), err
}

func TestExitMapping(t *testing.T) {
	const evidence = `{"deploy_check":{"verdict":"x"}}`
	cases := []struct {
		name       string
		childCode  int
		enforce    bool
		wantCode   int // exit.CodeFor(err); exit.OK for nil
		wantStdout bool
	}{
		{"matches", 0, false, exit.OK, true},
		{"under_permissioned always red", 12, false, exit.DeployCheckUnderPermissioned, true},
		{"under_permissioned red under enforce too", 12, true, exit.DeployCheckUnderPermissioned, true},
		{"not_minimized advisory by default", 10, false, exit.OK, true},
		{"not_minimized red under enforce", 10, true, exit.DeployCheckNotMinimized, true},
		{"over_permissioned advisory by default", 11, false, exit.OK, true},
		{"over_permissioned red under enforce", 11, true, exit.DeployCheckOverPermissioned, true},
		{"cannot-run", 3, false, exit.DeployCheckCannotRun, false},
		{"spec error maps to Runtime", 1, false, exit.Runtime, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdoutBody := evidence
			stderrBody := ""
			if !tc.wantStdout {
				// failure paths print only to stderr, no evidence JSON
				stdoutBody, stderrBody = "", "compose_derive: boom"
			}
			dir, compose := stubEnv(t, stdoutBody, stderrBody, tc.childCode)
			var extra []string
			if tc.enforce {
				extra = []string{"--enforce"}
			}
			out, _, err := run(t, dir, compose, extra...)
			if got := exit.CodeFor(err); got != tc.wantCode {
				t.Errorf("exit code = %d, want %d (err=%v)", got, tc.wantCode, err)
			}
			if tc.wantStdout && !strings.Contains(out, `"deploy_check"`) {
				t.Errorf("expected evidence JSON on stdout, got %q", out)
			}
			if !tc.wantStdout && out != "" {
				t.Errorf("expected no stdout on failure path, got %q", out)
			}
		})
	}
}

func TestEvidenceWrittenToOut(t *testing.T) {
	const evidence = `{"deploy_check":{"verdict":"matches"}}`
	dir, compose := stubEnv(t, evidence, "", 0)
	outFile := filepath.Join(t.TempDir(), "evidence.json")
	if _, _, err := run(t, dir, compose, "--out", outFile); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read --out: %v", err)
	}
	if !strings.Contains(string(got), `"deploy_check"`) {
		t.Errorf("--out file = %q, want evidence JSON", got)
	}
	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("--out perm = %o, want 600 (evidence is root-written)", perm)
	}
}

func TestCorrectnessPassedToChild(t *testing.T) {
	// The stub echoes $CORRECTNESS so we can assert the env wiring.
	dir := t.TempDir()
	script := "#!/usr/bin/env bash\necho \"{\\\"correctness\\\":\\\"$CORRECTNESS\\\"}\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, deriveScript), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	compose := filepath.Join(dir, "c.yml")
	if err := os.WriteFile(compose, []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, dir, compose, "--correctness", "/oracle/svc.sh")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "/oracle/svc.sh") {
		t.Errorf("CORRECTNESS not passed to child; stdout=%q", out)
	}
}

func TestUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	cases := [][]string{
		{},                     // no flags
		{"--compose", "x.yml"}, // missing --service
		{"--service", "svc"},   // missing --compose
		{"--compose", "/nope.yml", "--service", "svc"}, // compose does not exist
	}
	for _, args := range cases {
		out.Reset()
		errb.Reset()
		err := RunDeployCheck(args, &out, &errb)
		if got := exit.CodeFor(err); got != exit.Usage {
			t.Errorf("args %v: exit code = %d, want %d (EX_USAGE)", args, got, exit.Usage)
		}
	}
}

func TestMissingScriptIsUsageError(t *testing.T) {
	compose := filepath.Join(t.TempDir(), "c.yml")
	if err := os.WriteFile(compose, []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	err := RunDeployCheck([]string{"--compose", compose, "--service", "svc", "--script-dir", "/does/not/exist"}, &out, &errb)
	if got := exit.CodeFor(err); got != exit.Usage {
		t.Errorf("missing script: exit code = %d, want %d", got, exit.Usage)
	}
}
