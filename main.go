// csd — container-sec-derive.
//
// v0.1.0-alpha scope (PLAN.md): subprocess `ig run trace_capabilities`,
// parse line-delimited JSON events, filter to one container, print the
// distinct cap set to stdout, exit. No formatters, no sidecar, no verify.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

// capEvent is the subset of ig trace_capabilities fields we consume.
// IG's full schema is larger; we decode only what the aggregator needs
// so a minor IG schema drift in unused fields doesn't break us.
type capEvent struct {
	Timestamp int64  `json:"timestamp"`
	Comm      string `json:"comm"`
	Pid       int    `json:"pid"`
	Syscall   string `json:"syscall"`
	CapName   string `json:"capName"`
	Cap       int    `json:"cap"`
	Container struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Image string `json:"image"`
	} `json:"container"`
}

// traceHealthEvent is IG's periodic ringbuf-health message. PLAN.md
// §Event-loss reporting requires these counters be surfaced on every
// run. Schema here is our best-effort; Step 11's IG version pin will
// lock it against an upstream release.
type traceHealthEvent struct {
	Type           string `json:"type"`
	EventsRecorded int    `json:"events_recorded"`
	EventsDropped  int    `json:"events_dropped"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "csd:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("csd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		container     = fs.String("container", "", "target container id or name (required unless --fixture)")
		fixture       = fs.String("fixture", "", "read ig-format NDJSON from this file instead of spawning ig")
		duration      = fs.Duration("duration", 30*time.Second, "observation window (ignored in --fixture mode)")
		igBin         = fs.String("ig", "ig", "path to the ig binary")
		initWindowMs  = fs.Int("init-window-ms", 500, "drop capability events observed within this many ms of the first matching event (0 disables)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *fixture == "" && *container == "" {
		return errors.New("--container is required (or pass --fixture <file> to read pre-captured events)")
	}

	var (
		src io.ReadCloser
		err error
	)
	if *fixture != "" {
		src, err = os.Open(*fixture)
		if err != nil {
			return fmt.Errorf("open fixture: %w", err)
		}
		defer src.Close()
		s, err := aggregate(src, *container, *initWindowMs)
		if err != nil {
			return err
		}
		printCaps(stdout, s.CapNames())
		return nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeoutCancel := context.WithTimeout(ctx, *duration)
	defer timeoutCancel()

	s, err := observe(ctx, *igBin, *container, *initWindowMs)
	if err != nil {
		return err
	}
	printCaps(stdout, s.CapNames())
	return nil
}

// observe spawns `ig run trace_capabilities --output json` and aggregates
// events for the lifetime of ctx.
func observe(ctx context.Context, igBin, container string, initWindowMs int) (*Sidecar, error) {
	cmd := exec.CommandContext(ctx, igBin, "run", "trace_capabilities", "--output", "json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", igBin, err)
	}
	s, aggErr := aggregate(stdout, container, initWindowMs)
	// Wait for ig to exit. A context-cancel kill is the normal termination
	// path for the timed observation window, so we don't propagate that as
	// an error.
	waitErr := cmd.Wait()
	if aggErr != nil && !errors.Is(aggErr, io.EOF) {
		return nil, aggErr
	}
	if waitErr != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("ig exited: %w", waitErr)
	}
	return s, nil
}

// aggregate reads NDJSON events from r, filters to the given container
// (by id or name; empty string matches all), and returns a *Sidecar whose
// Capabilities slice holds the sorted distinct caps.
//
// initWindowMs drops events observed within that many milliseconds of the
// first matching event, reducing runc / ld.so init noise. 0 disables the
// filter. Suppressed-event count is recorded on Target so reviewers can
// tell the filter apart from a genuinely small cap set.
//
// Timestamps are assumed to be milliseconds (fixture convention, matching
// `ig run trace_capabilities --output json` at the pinned release). Revisit
// if Step 11's IG version pin exposes a different unit.
func aggregate(r io.Reader, container string, initWindowMs int) (*Sidecar, error) {
	seen := map[string]struct{}{}
	var (
		firstTsMs      int64
		firstSeen      bool
		suppressed     int
		latestHealth   *traceHealthEvent
	)
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	for scan.Scan() {
		line := scan.Bytes()
		if len(line) == 0 {
			continue
		}
		// Type-discriminate: trace_health / diagnostic lines are decoded
		// first and never flow into the capability aggregator. Untagged
		// lines fall through to the capEvent path (IG emits cap events
		// without a "type" field at the pinned release).
		var env struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &env); err == nil && env.Type == "trace_health" {
			var th traceHealthEvent
			if err := json.Unmarshal(line, &th); err == nil {
				latestHealth = &th
			}
			continue
		}
		var ev capEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			// Skip malformed lines rather than abort the observation
			// window. Real IG output can include non-event diagnostic
			// lines on some versions.
			continue
		}
		if !matchesContainer(ev, container) {
			continue
		}
		if !firstSeen {
			firstTsMs = ev.Timestamp
			firstSeen = true
		}
		if initWindowMs > 0 && ev.Timestamp-firstTsMs < int64(initWindowMs) {
			suppressed++
			continue
		}
		name := normalizeCap(ev.CapName)
		if name == "" {
			continue
		}
		seen[name] = struct{}{}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(seen))
	for k := range seen {
		names = append(names, k)
	}
	sort.Strings(names)
	s := NewSidecar()
	s.Target.InitWindowSuppressed = suppressed
	if latestHealth != nil {
		s.TraceHealth.EventsRecorded = latestHealth.EventsRecorded
		s.TraceHealth.EventsDropped = latestHealth.EventsDropped
		if latestHealth.EventsRecorded > 0 {
			s.TraceHealth.DropRate = float64(latestHealth.EventsDropped) / float64(latestHealth.EventsRecorded)
		}
	}
	for _, n := range names {
		s.Capabilities = append(s.Capabilities, Capability{Name: n})
	}
	return s, nil
}

func matchesContainer(ev capEvent, target string) bool {
	if target == "" {
		return true
	}
	if ev.Container.ID == target || ev.Container.Name == target {
		return true
	}
	// Accept a short prefix match on the container id, matching docker's
	// usual ergonomics (e.g. `docker ps` shows a 12-char prefix).
	if len(target) >= 6 && strings.HasPrefix(ev.Container.ID, target) {
		return true
	}
	return false
}

// normalizeCap strips the CAP_ prefix so output is consistent regardless
// of whether IG emits "CAP_NET_RAW" or "NET_RAW" for a given release.
func normalizeCap(name string) string {
	name = strings.ToUpper(strings.TrimSpace(name))
	return strings.TrimPrefix(name, "CAP_")
}

func printCaps(w io.Writer, caps []string) {
	for _, c := range caps {
		fmt.Fprintln(w, c)
	}
}
