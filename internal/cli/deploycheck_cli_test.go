package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tmatens/container-sec-derive/internal/exit"
)

// TestDeployCheckDispatch proves `csd deploy-check` routes to the subcommand
// through Run (the top-level dispatch), not the observe flag parser. A bare
// invocation is enough: it reaches deploycheck.RunDeployCheck's own required-
// flag check (EX_USAGE) rather than "one of --container or --image is
// required", which is what the observe path would emit. No docker/ig needed.
func TestDeployCheckDispatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"deploy-check"}, &stdout, &stderr)
	if got := exit.CodeFor(err); got != exit.Usage {
		t.Fatalf("exit code = %d, want %d (EX_USAGE)", got, exit.Usage)
	}
	if err == nil || !strings.Contains(err.Error(), "deploy-check requires") {
		t.Errorf("error = %v, want the deploy-check usage message (proves dispatch, not observe path)", err)
	}
}

// TestDeployCheckHelpDispatch confirms --help on the subcommand is handled by
// its flagset (clean exit, no error) rather than falling through.
func TestDeployCheckHelpDispatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run([]string{"deploy-check", "--help"}, &stdout, &stderr); err != nil {
		t.Fatalf("deploy-check --help returned error: %v", err)
	}
}
