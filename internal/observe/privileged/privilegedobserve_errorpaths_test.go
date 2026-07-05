package privileged

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tmatens/container-sec-derive/internal/attrib"
	"github.com/tmatens/container-sec-derive/internal/exit"
	"github.com/tmatens/container-sec-derive/internal/ig"
	"github.com/tmatens/container-sec-derive/internal/obstest"
)

// Error-path / cleanup coverage for the privileged observer's dual-gadget
// pipeline (#284). The happy fixture paths live in privilegedobserve_test.go;
// these exercise the failure and deadline paths the -race detector alone can't
// assert: a gadget failing on the concurrent live path, the observation window
// expiring, fixture-open failures, one half short-circuiting the other, and the
// ambiguity error mapping to the right exit code.
//
// The live-path tests drive a fake `ig` (obstest.FakeIGRun / fakeIGSleep) so the
// concurrent goroutine launch + join is real without a kernel; the true eBPF
// two-gadget path is validated by the scheduled smoke_device.sh privileged gate.

// runWithTimeout runs ProducePrivilegedObservation and fails if it does not
// return within bound — the guard against a wg.Wait / context-propagation hang.
func runWithTimeout(t *testing.T, opts PrivilegedPipelineOpts, bound time.Duration) error {
	t.Helper()
	type res struct{ err error }
	ch := make(chan res, 1)
	go func() {
		_, err := ProducePrivilegedObservation(opts, io.Discard)
		ch <- res{err}
	}()
	select {
	case r := <-ch:
		return r.err
	case <-time.After(bound):
		t.Fatalf("ProducePrivilegedObservation did not return within %s (hang on the concurrent path)", bound)
		return nil
	}
}

// fakeIGSleep is FakeIGRun's long-running cousin: `run` blocks in sleep so the
// observation deadline (not process exit) is what ends the capture.
func fakeIGSleep(t *testing.T, seconds int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ig-fake-sleep")
	// `exec sleep` replaces the shell so the process the context tracks IS the
	// sleep: SIGKILL on deadline closes the stdout pipe directly. A plain
	// `sleep` would leave an orphaned grandchild holding the pipe open, hanging
	// cmd.Wait — a fake-ig artifact, not a code path under test.
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  version) echo " + ig.PinnedIGVersion + "; exit 0;;\n" +
		"  run) exec sleep " + strconv.Itoa(seconds) + ";;\n" +
		"esac\nexit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProducePrivileged_ConcurrentGadgetFailurePropagates(t *testing.T) {
	// Live path (no fixtures): both gadgets spawn the fake ig, which emits a
	// malformed NDJSON line. Each aggregator hard-fails (deep-review L3), so both
	// goroutines error. The function must join both and surface an error without
	// hanging or panicking.
	fake := obstest.FakeIGRun(t, "{ not valid json\n", "")
	err := runWithTimeout(t, PrivilegedPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "x", InitWindowMs: 0},
		IGBin:         fake,
		Duration:      2 * time.Second,
	}, 30*time.Second)
	if err == nil {
		t.Fatal("expected an error when the concurrent gadgets emit malformed input")
	}
}

func TestProducePrivileged_DeadlineCancelsWithoutHanging(t *testing.T) {
	// The gadget subprocesses block far longer than the window; the deadline must
	// propagate through the shared context to cancel both, and the call must
	// return promptly — well under the 60s sleep — not wait it out.
	fake := fakeIGSleep(t, 60)
	start := time.Now()
	_ = runWithTimeout(t, PrivilegedPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "x", InitWindowMs: 0},
		IGBin:         fake,
		Duration:      1 * time.Second,
	}, 30*time.Second)
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("call took %s; the deadline should cancel the gadgets near the 1s window, not run the 60s sleep", elapsed)
	}
}

func TestProducePrivileged_FixtureOpenErrors(t *testing.T) {
	goodCaps := obstest.WriteTemp(t, "caps.ndjson", obstest.PrivCapsFixture)
	cases := []struct {
		name string
		opts PrivilegedPipelineOpts
		want string
	}{
		{"missing caps fixture", PrivilegedPipelineOpts{Fixture: "/nonexistent/caps.ndjson"}, "open fixture"},
		{"missing device fixture", PrivilegedPipelineOpts{Fixture: goodCaps, DeviceFixture: "/nonexistent/dev.ndjson"}, "open device-fixture"},
		{"missing fixture-stderr", PrivilegedPipelineOpts{Fixture: goodCaps, FixtureStderr: "/nonexistent/err.txt"}, "open fixture-stderr"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.opts.AggregateOpts = attrib.Opts{Container: "gpu-1", InitWindowMs: 0}
			_, err := ProducePrivilegedObservation(c.opts, io.Discard)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want one containing %q", err, c.want)
			}
		})
	}
}

func TestProducePrivileged_CapsFailureShortCircuitsDeviceHalf(t *testing.T) {
	// A malformed caps fixture must fail the whole run before the device half is
	// touched (the err == nil guard), so a bad caps stream can't silently yield a
	// devices-only partial decomposition.
	badCaps := obstest.WriteTemp(t, "bad-caps.ndjson", "{ not json\n")
	goodDev := obstest.WriteTemp(t, "dev.ndjson", obstest.PrivDevFixture)
	_, err := ProducePrivilegedObservation(PrivilegedPipelineOpts{
		AggregateOpts: attrib.Opts{Container: "gpu-1", InitWindowMs: 0},
		Fixture:       badCaps,
		DeviceFixture: goodDev,
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "parse trace_capabilities") {
		t.Fatalf("err = %v, want a trace_capabilities parse error (device half must not be reached)", err)
	}
}

func TestProducePrivileged_AmbiguousSelectionMappedToExitCode(t *testing.T) {
	// Two replicas match --image without --all-matching: caps.Aggregate returns a
	// typed AmbiguousSelectionError, which the privileged path must remap to the
	// TargetAmbiguous exit code (not a bare error).
	nd := obstest.PrivCapsFixture + "\n" +
		`{"timestamp":1700000006000,"cap":"CAP_SYS_NICE","capable":true,` +
		`"proc":{"comm":"vpn2","pid":6001},` +
		`"runtime":{"runtimeName":"docker","containerId":"ddd444ddd444","containerName":"gpu-2","containerImageName":"gpu:1"}}`
	fx := obstest.WriteTemp(t, "two-replicas.ndjson", nd)
	_, err := ProducePrivilegedObservation(PrivilegedPipelineOpts{
		AggregateOpts: attrib.Opts{Image: "gpu:1", InitWindowMs: 0},
		Fixture:       fx,
	}, io.Discard)
	if err == nil {
		t.Fatal("expected ambiguity error for --image matching two replicas")
	}
	if got := exit.CodeFor(err); got != exit.TargetAmbiguous {
		t.Errorf("exit code = %d, want TargetAmbiguous (%d); err=%v", got, exit.TargetAmbiguous, err)
	}
}
