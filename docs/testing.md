# Testing strategy

How `csd` is tested, what each tier *proves*, and where it runs. The guiding
fact: csd's job is to observe a real kernel, so its correctness has a part that
is **only** provable live. This document maps that out so the gap is explicit and
trackable, not implicit.

## The core truth

`--fixture <ndjson>` replays a pre-captured event stream through the **entire**
pipeline (attribution → aggregation → decision → all seven formatters → sidecar),
so the hermetic tests prove the *transform* is correct. They cannot prove:

1. that `ig` + eBPF actually **produces** that stream for a real workload — i.e.
   that attach + container attribution work on a real kernel, and that our
   committed fixtures match what the pinned `ig` really emits;
2. that a **derived config actually works** when applied to the container — the
   ultimate "meets intent" check;
3. behavior across **kernel versions** or against **real hardware devices**.

Each of those needs a real host. The tiers below say which.

## Test tiers

| Tier | Proves | Where it runs | Status |
|---|---|---|---|
| Static analysis (`go vet`, CodeQL, govulncheck) | No obvious bugs / known CVEs / scanning | `ci.yml`, `codeql.yml`, `govulncheck.yml` | ✅ |
| Unit + golden + `--fixture` pipeline | The transform: aggregation, decision logic, every formatter, the sidecar schema, exit codes | local + `ci.yml` | ✅ (the hermetic core) |
| Fuzz | Parser robustness on hostile input | `ci.yml` (CPU-bounded) | ⚠️ partial — v0.2 parsers have targets; **`capadd` NDJSON + `compose-patch` rewriter not yet fuzzed** (#116) |
| Live-BPF integration smokes | Attach + attribution + `ig`-schema conformance, on a real kernel | `integration.yml` on **GitHub-hosted** runners (`scripts/smoke_{wsl2,fs,device,capadd}.sh`) | ✅ baseline (one kernel, hardware-free) |
| Closed-loop "meets intent" | A **derived config actually works** (and a tighter one breaks) | real host / self-hosted runner | ❌ **missing** (#116) — highest-value gap |
| Hardware-ful device | Real `/dev/dri` / `/dev/net/tun` / `/dev/kvm` detection | self-hosted runner with that hardware | ❌ missing (#116) |
| Kernel/distro matrix | BPF attach across kernels (incl. the future LSM-BPF path, kernel ≥5.7) | self-hosted runner(s) / VM matrix | ❌ missing (#116) |
| Dogfooding | csd against the real target stack | the homelab host | ❌ missing (#116) |

## The hermetic core (fully testable without a kernel)

This is everything except attach/attribution, and it is the bulk of the code.
Run it anywhere:

```sh
# /tmp is noexec in some sandboxes; go test forks a helper, so redirect TMPDIR.
export TMPDIR="$HOME/.gotmp" GOTMPDIR="$HOME/.gotmp"; mkdir -p "$TMPDIR"
go vet ./...
go test ./...                 # unit + golden + fixture-driven pipeline
go test -race ./...           # concurrency (the observe goroutines, the privileged two-stream merge)
go test -cover ./...          # coverage
go test ./... -update-golden  # regenerate goldens after an intentional schema change (never silently)
```

`--fixture` (NDJSON), `--mounts-fixture`, `--inspect-fixture`, `--device-fixture`,
and `--fixture-stderr` make every observer runnable with zero `ig`/docker/BPF, so
the CLI end-to-end (`--observe × --format`) is exercisable hermetically.

## The live tier (needs a real kernel)

`integration.yml` runs the `scripts/smoke_*.sh` gates on GitHub-hosted
`ubuntu-24.04` runners, which provide a real kernel + `sudo` + docker — enough for
`ig`/BPF. Each smoke uses a **deterministic, hardware-free hard gate** (e.g. the
synthetic exerciser; a `--device /dev/null:/dev/csd-exerciser-dev` mapping for
devices; the exerciser's CHOWN/SETUID/SETGID checks for capadd). Reference images
are informational (they can legitimately observe zero post-attach events — see
`docs/known-deltas.md`). Locally these need docker + the pinned `ig` + root:
`make smoke-wsl2 / smoke-fs / smoke-device / smoke-capadd`.

## What the `claude-station` sandbox cannot do

The agent that develops csd runs in a hardened container with **no docker, no
`ig`, no `CAP_BPF`, no `--pid=host`, non-root**. So it can run the entire hermetic
core (and does, as the merge gate it can verify locally), but **cannot** run any
live-BPF smoke, the kernel-pin gate against a real `ig`, real `docker inspect`,
the image build/sign/publish, or arm64 execution. Those are delegated to CI
(hosted runners) and, for the gaps above, to a real host. This is by design, not a
limitation to work around.

## Closing the gap

The outstanding live/host tiers and the repo-side work that enables them are
tracked in **issue #116**. The priority order:

1. **Closed-loop harness** (`scripts/closed_loop.sh`) — derive → relaunch with the
   derived config → re-run the workload → assert it still works, then assert a
   tighter config fails. Hardware-free, so it runs on hosted runners *and* a
   self-hosted one. This is the only test that proves a derived profile is
   *correct*, not just internally consistent — it is `csd verify` extended to
   actually apply the config.
2. **Fuzz the v0.4 parsers** — close the hermetic-tier fuzz gap (no host needed).
3. **Hardware-ful device smoke + kernel matrix** — self-hosted runner.
4. **Dogfood** against the real stack.

A **decision precedes the self-hosted items**: a runner executing PR code with
root + BPF is a supply-chain risk (csd PRs are agent-authored), so either a
trust-gated **GitHub self-hosted runner** or a **Forgejo mirror + Forgejo runner**
(privileged CI inside the homelab trust boundary) — never running untrusted/fork
PR code privileged. See #116.
