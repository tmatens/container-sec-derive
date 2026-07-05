package ig

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"

	"github.com/tmatens/container-sec-derive/internal/exit"
)

// RunGadget is the signal-acquisition seam: it spawns
// `igBin run <gadgetRef> <gadgetArgs...>` and streams the gadget's stdout into
// consume, while draining ig's stderr through ParseIGStderr so the ringbuf-loss
// counter (v0.51.0 emits these as stderr warnings, not typed stdout events) is
// returned to the caller. Every observer acquires its signal through this
// function rather than shelling out to `ig` directly, so an alternate backend —
// the LSM-BPF migration, or a csd-owned gadget — plugs in here, not across every
// observer. See docs/organization.md §2 (the internal/ig seam).
//
// consume aggregates the gadget's stdout for the lifetime of ctx (the gadget
// streams until ctx is cancelled). An error it returns that is not io.EOF is
// treated as an early bailout (e.g. an oversized untrusted stdout line, or a
// target-selection ambiguity): ig's stdout pipe is left undrained, so ig would
// block on the full pipe and never exit — RunGadget kills it immediately rather
// than let cmd.Wait() stall for the rest of the --duration window, and returns
// that error. A normal ctx-cancel kill is the expected end of the timed window,
// so a wait error it produces is not propagated.
//
// The returned lost count is the ringbuf-loss total; callers record it on their
// observation's trace_health. On any error the zero value of T is returned.
func RunGadget[T any](
	ctx context.Context,
	igBin, gadgetRef string,
	gadgetArgs []string,
	stderrSink io.Writer,
	consume func(stdout io.Reader) (T, error),
) (T, int, error) {
	var zero T
	cmd := exec.CommandContext(ctx, igBin, append([]string{"run", gadgetRef}, gadgetArgs...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return zero, 0, fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return zero, 0, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		if exit.IsIGMissing(err) {
			return zero, 0, exit.WrapCoded(exit.IGMissing, fmt.Errorf("ig binary %q not available: %w", igBin, err))
		}
		return zero, 0, fmt.Errorf("start %s: %w", igBin, err)
	}

	var (
		wg   sync.WaitGroup
		lost int
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		lost = ParseIGStderr(stderrPipe, stderrSink)
	}()

	result, aggErr := consume(stdout)
	earlyErr := aggErr != nil && !errors.Is(aggErr, io.EOF)
	if earlyErr {
		_ = cmd.Process.Kill()
	}
	// Join the stderr-drain goroutine BEFORE cmd.Wait(): Wait closes the pipe,
	// and the documented StderrPipe contract requires the read to finish first,
	// else an in-flight Read can drop a trailing `lost N` line. The join
	// happens-before the lost read below, so no extra synchronisation is needed.
	wg.Wait()
	waitErr := cmd.Wait()
	if earlyErr {
		return zero, lost, aggErr
	}
	if waitErr != nil && ctx.Err() == nil {
		return zero, lost, fmt.Errorf("ig exited: %w", waitErr)
	}
	return result, lost, nil
}
