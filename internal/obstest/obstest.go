// Package obstest holds test-only helpers shared across the observer
// packages' test suites (and the root CLI tests). It is imported solely from
// *_test.go files, so it never reaches the csd binary; it exists because Go
// requires a package's white-box tests to live in that package's directory, so
// helpers used by more than one such package need a shared importable home.
package obstest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/ig"
	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// WriteTemp writes content to a uniquely-named temp file and returns its path.
func WriteTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := t.TempDir() + "/" + name
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// EqualSlice reports whether a and b have the same elements in the same order.
func EqualSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FakeIGRun writes a fake `ig` shell script that prints PinnedIGVersion on
// `version` and replays stdoutNDJSON/stderrText on `run`. Returns its path,
// suitable for --ig in a run()/observe test.
func FakeIGRun(t *testing.T, stdoutNDJSON, stderrText string) string {
	t.Helper()
	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.ndjson")
	errFile := filepath.Join(dir, "err.txt")
	if err := os.WriteFile(outFile, []byte(stdoutNDJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errFile, []byte(stderrText), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ig-fake")
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  version) echo " + ig.PinnedIGVersion + "; exit 0;;\n" +
		"  run) cat " + outFile + "; cat " + errFile + " >&2; exit 0;;\n" +
		"esac\n" +
		"exit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// ContainsSubstr reports whether any element of ss contains sub.
func ContainsSubstr(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// PrivCapsFixture / PrivDevFixture are the trace_capabilities / trace_open
// NDJSON the privileged-composition tests replay (a gpu workload holding
// CAP_NET_ADMIN + CAP_SYS_NICE and opening /dev/dri/card0 + /dev/net/tun).
const PrivCapsFixture = `{"timestamp":1700000005000,"syscall":"socket","cap":"CAP_NET_ADMIN","cap_raw":12,"capable":true,"proc":{"comm":"vpn","pid":5001},"runtime":{"runtimeName":"docker","containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
{"timestamp":1700000007000,"syscall":"ioctl","cap":"CAP_SYS_NICE","cap_raw":23,"capable":true,"proc":{"comm":"renderer","pid":5002},"runtime":{"runtimeName":"docker","containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
`

const PrivDevFixture = `{"syscall":"openat","flags_raw":2,"fpath":"/dev/dri/card0","proc":{"comm":"renderer"},"runtime":{"containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
{"syscall":"openat","flags_raw":1,"fpath":"/dev/null","proc":{"comm":"renderer"},"runtime":{"containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
{"syscall":"openat","flags_raw":2,"fpath":"/dev/net/tun","proc":{"comm":"vpn"},"runtime":{"containerId":"ccc333ccc333","containerName":"gpu-1","containerImageName":"gpu:1"}}
`

// MakeSidecar builds a minimal valid Sidecar with the named caps plus optional
// knobs. Tests use it instead of inlining literal sidecar JSON so a future
// schema-additive bump touches one helper.
func MakeSidecar(image, digest, workload string, durationSeconds int, caps ...string) *sidecar.Sidecar {
	s := sidecar.NewSidecar()
	s.Image = image
	s.ImageDigest = digest
	s.Workload = workload
	s.DurationSeconds = durationSeconds
	for _, c := range caps {
		s.Capabilities = append(s.Capabilities, sidecar.Capability{
			Name:              c,
			EventCount:        1,
			FirstSeenOffsetMs: 0,
			LastSeenOffsetMs:  0,
			CommSamples:       []string{c + "-sample"},
		})
	}
	return s
}
