// Package ig is csd's signal-acquisition seam: it owns the Inspektor Gadget
// version pin, the gadget OCI references, the `ig version` schema gate, and
// the ig-stderr drop-counter parsing. Observers depend on this package rather
// than reaching for os/exec and the gadget tags directly, so an alternate
// signal backend (an LSM-BPF hook, a csd-authored gadget, or a non-ig source)
// is a localized change here and not a sweep across every observer
// (see docs/organization.md §Seams and ROADMAP §LSM-BPF migration).
//
// It is a foundation package: it imports only internal/exit and the stdlib.
package ig

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tmatens/container-sec-derive/internal/exit"
)

// Pinned IG release. v0.1 targets a single upstream version; MIN/MAX
// equal the pin until we've smoke-tested against a widening window.
// PLAN.md §IG version pinning defines the v1 semantics. Step 33
// promoted the version-mismatch path from warn-and-continue to a
// hard exit.SchemaMismatch (CheckIGVersion below); the fixture path
// is unaffected because produceObservation short-circuits to
// aggregate() before CheckIGVersion runs.
//
// The Makefile and the release/image/integration workflows extract
// PinnedIGVersion from this file by an awk match on the `PinnedIGVersion =`
// line — keep the declaration on a single line so that extraction stays valid.
const (
	PinnedIGVersion    = "v0.51.0"
	MinIGVersion       = "v0.51.0"
	MaxTestedIGVersion = "v0.51.0"

	// TraceCapabilitiesGadget is the OCI reference ig pulls to run the
	// trace_capabilities gadget. ig v0.51.0 is fully image-based: a bare
	// "trace_capabilities" is not a valid argument to `ig run`. We tag to
	// PinnedIGVersion so the gadget image and the ig binary advance
	// together; bumping the pin means re-pulling this tag.
	TraceCapabilitiesGadget = "ghcr.io/inspektor-gadget/gadget/trace_capabilities:" + PinnedIGVersion

	// TraceOpenGadget is the OCI reference for the trace_open gadget, the
	// signal source for the v0.2 read-only-filesystem observer: it traces
	// open/openat and reports the open flags (so write-intent opens can be
	// filtered) and the symlink-resolved full path (with --paths). Tagged
	// to PinnedIGVersion in lockstep with TraceCapabilitiesGadget — bumping
	// the pin re-pulls both. See ROADMAP §v0.2 and the design in issue #77.
	TraceOpenGadget = "ghcr.io/inspektor-gadget/gadget/trace_open:" + PinnedIGVersion

	// TraceTcpGadget is the OCI reference for the trace_tcp gadget, the
	// signal source for the v0.8 network-egress observer: it reports TCP
	// connect/accept/close with the L4 endpoints. Tagged to PinnedIGVersion
	// in lockstep with the other gadgets.
	TraceTcpGadget = "ghcr.io/inspektor-gadget/gadget/trace_tcp:" + PinnedIGVersion

	// TraceDnsGadget is the OCI reference for the trace_dns gadget, the second
	// signal source for the v0.8 egress observer's DNS/hostname follow-up
	// (issue #159): it reports DNS queries and responses with the queried name,
	// the resolved addresses, and the resolver endpoint. trace_tcp is TCP-only
	// and IP-based; trace_dns supplies the IP→hostname correlation and the
	// UDP/53 resolver destination trace_tcp cannot see. The signal survey
	// (issue #159) confirmed the gadget and its field schema exist at the pin —
	// no pin bump. Tagged to PinnedIGVersion in lockstep with the other gadgets.
	TraceDnsGadget = "ghcr.io/inspektor-gadget/gadget/trace_dns:" + PinnedIGVersion
)

// igLostSamplesRE matches ig's ringbuf-loss stderr warnings. v0.51.0
// emits these as logrus-formatted lines rather than typed stdout
// events; parsing them is the only way to surface drop counts on
// real hosts. PLAN.md §Event-loss reporting.
var igLostSamplesRE = regexp.MustCompile(`lost (\d+) samples`)

// ParseIGStderr drains ig's stderr stream to sink and returns the total
// ringbuf-lost sample count it reported. ReadString has no line cap, so an
// outsized line is read through and parsing continues, and it always reads to
// EOF so the stderr pipe is fully drained (it can never block the observe path).
func ParseIGStderr(r io.Reader, sink io.Writer) int {
	total := 0
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			if sink != nil {
				fmt.Fprintln(sink, line)
			}
			m := igLostSamplesRE.FindStringSubmatch(line)
			if len(m) == 2 {
				if n, convErr := strconv.Atoi(m[1]); convErr == nil {
					total += n
				}
			}
		}
		if err != nil { // io.EOF or a read error: stream is exhausted
			break
		}
	}
	return total
}

// igVersionCheckTimeout bounds the `ig version` probe in CheckIGVersion. ig
// version is near-instant; this is a generous ceiling that only fires if the
// binary hangs.
const igVersionCheckTimeout = 10 * time.Second

// CheckIGVersion runs `ig version` and returns exit.SchemaMismatch when
// the detected release is outside [MinIGVersion, MaxTestedIGVersion].
// ig v0.51.0 does not support --output json on `version`; the
// subcommand emits a single plain-text line like "v0.51.0". We take
// the first whitespace-delimited token so future ig releases that
// add trailing metadata still parse.
//
// Step 33 promotes this to a hard SchemaMismatch exit per PLAN.md
// §IG version pinning. Phase A (Steps 11.1..32) was warn-and-continue
// so we'd learn about drift without breaking fixture-only users; the
// fixture path doesn't reach this function (produceObservation
// short-circuits to aggregate() before the version check), so the
// hard-fail only affects live observe.
//
// Failures of `ig version` itself (binary missing, exec error) are
// NOT treated as SchemaMismatch — observe() will surface exit.IGMissing
// for the same condition. Returning nil here keeps the version-check
// out of that error's blast radius.
func CheckIGVersion(igBin string, stderr io.Writer) error {
	// Bound the probe and honor Ctrl-C/SIGTERM: a hung `ig version` used to
	// ignore both because it ran via context-less exec.Command (deep-review L1).
	// The signal context is short-lived (just this probe) — the observe path
	// installs its own afterwards.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeoutCancel := context.WithTimeout(ctx, igVersionCheckTimeout)
	defer timeoutCancel()
	out, err := exec.CommandContext(ctx, igBin, "version").Output()
	if err != nil {
		if stderr != nil {
			fmt.Fprintf(stderr, "csd: ig version check skipped: %v\n", err)
		}
		return nil
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return nil
	}
	detected := fields[0]
	if detected == "" {
		return nil
	}
	if detected != PinnedIGVersion {
		return exit.CodedErrorf(exit.SchemaMismatch,
			"ig %s detected, PINNED_IG_VERSION=%s (tested window %s..%s); refusing to parse — see PLAN.md §IG version pinning",
			detected, PinnedIGVersion, MinIGVersion, MaxTestedIGVersion,
		)
	}
	return nil
}
