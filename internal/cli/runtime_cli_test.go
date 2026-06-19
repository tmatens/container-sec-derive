package cli

import (
	"bytes"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
)

const capsFixture = "../../testdata/ig-versions/v0.51.0/sample.ndjson"

// An unsupported --runtime is rejected with EX_USAGE before any observe work.
func TestRun_RuntimeFlag_Invalid(t *testing.T) {
	var out, errBuf bytes.Buffer
	err := Run([]string{
		"--observe", "caps", "--container", "x",
		"--fixture", capsFixture, "--format", "json", "--runtime", "containerd",
	}, &out, &errBuf)
	if exit.CodeFor(err) != exit.Usage {
		t.Errorf("--runtime containerd: exit = %d, want exit.Usage (%d); err=%v", exit.CodeFor(err), exit.Usage, err)
	}
}

// --runtime docker|podman are both accepted; in fixture mode the inspect path is
// skipped, so neither shells out — this just proves the flag is wired and
// validated without breaking the pipeline.
func TestRun_RuntimeFlag_Accepted(t *testing.T) {
	for _, rt := range []string{"docker", "podman"} {
		var out, errBuf bytes.Buffer
		err := Run([]string{
			"--observe", "caps", "--container", "x",
			"--fixture", capsFixture, "--format", "json", "--runtime", rt,
		}, &out, &errBuf)
		if err != nil {
			t.Errorf("--runtime %s (fixture mode): unexpected error: %v (stderr=%s)", rt, err, errBuf.String())
		}
	}
}
