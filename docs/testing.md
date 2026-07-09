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

   > **Fixture-vs-live naming (learned the hard way, #349 scenario 6).** The
   > committed NDJSON fixtures were hand-authored with *idealized* field values that
   > did **not** match real pinned-ig output — e.g. syscall names as the bare
   > lowercase `perf_event_open`/`openat`, whereas live ig v0.51.0 emits
   > `SYS_PERF_EVENT_OPEN` and (note) surfaces a libc `open()`/`openat()` as
   > `SYS_OPEN`. Logic keyed on the raw name (the capadd finer-cap KB) therefore
   > matched the fixtures but silently **missed live**, shipping a dead code path a
   > fixture-only test could never catch. csd now canonicalizes at the parse
   > boundary (`ig.NormalizeSyscall`, applied in `CapEvent`/`FileEvent`), and the
   > fixtures carry the real `SYS_`-prefixed names. **When authoring or bumping a
   > fixture, capture the real shape** — `scripts/capture_ig_naming.sh` dumps live
   > cap/syscall naming from the synthetic exerciser on the self-hosted runner — and
   > do not hand-idealize field values. (Sibling divergences already handled
   > leniently in `CapEvent`: `timestamp` is an RFC3339 *string* + `timestamp_raw`
   > ns int, not the fixtures' int-ms `timestamp`; `capable` is always present live.)
2. that a **derived config actually works** when applied to the container — the
   ultimate "meets intent" check;
3. behavior across **kernel versions** or against **real hardware devices**.

Each of those needs a real host. The tiers below say which.

## Test tiers

| Tier | Proves | Where it runs | Status |
|---|---|---|---|
| Static analysis (`go vet`, govulncheck) + CodeQL | No obvious bugs / known CVEs / scanning | `ci.yml`, `govulncheck.yml` per-PR; **`codeql.yml` every-3-days + dispatch** (temporary cost trim, #165 — not per-PR) | ✅ |
| Unit + golden + `--fixture` pipeline | The transform: aggregation, decision logic, every formatter, the sidecar schema, exit codes | local + `ci.yml` | ✅ (the hermetic core) |
| Fuzz | Parser robustness on hostile input | `ci.yml` (CPU-bounded, per-PR) + **ClusterFuzzLite weekly batch** (`cflite-batch.yml`, accumulating corpus, crash→issue; needs the build-tagged `go-118-fuzz-build` shim — #174) | ✅ ig NDJSON (`capEvent`/`fileEvent`) + `capadd` aggregator + `parseMountDestinations` + `compose-patch` rewriter + `aggregateEgress` + `aggregateDNS` |
| Live-BPF integration smokes | Attach + attribution + `ig`-schema conformance, on a real kernel | `integration.yml`, **GitHub-hosted** (`scripts/smoke_{wsl2,fs,device,capadd,egress}.sh`). **Per-PR: amd64, synthetic-only, 10s** (cost trim). **Every-3-days + dispatch: full reference set @30s + a native arm64 leg** | ✅ baseline (per-PR one kernel/amd64; arm64 + reference on the schedule) |
| Closed-loop "meets intent" | A **derived config actually works** (and a tighter one breaks) | hosted or self-hosted runner | ✅ `scripts/closed_loop.sh` / `make closed-loop`, in `integration.yml` (amd64; skipped on the arm64 leg — arch-agnostic) |
| Cross-runtime (podman) | `--runtime podman`: ig attach/attribution under podman + the podman inspect/history/mounts parse (#164) | `integration.yml`, **every-3-days schedule only** (not per-PR) | ✅ `scripts/smoke_podman.sh` / `make smoke-podman` — green on ubuntu-24.04 + rootful podman (caps + fs hard gates) |
| Hardware-ful device | Real `/dev/dri` / `/dev/net/tun` / `/dev/kvm` detection | self-hosted runner with that hardware | 🟡 scaffolded (`scripts/smoke_device_hw.sh` + `integration-selfhosted.yml`); needs a registered runner (#116) |
| Kernel/distro matrix | BPF attach across kernels (incl. the future LSM-BPF path, kernel ≥5.7) | self-hosted runner(s) / VM matrix | 🟡 scaffolded (the full suite runs on the self-hosted runner's kernel); a true matrix needs multiple runners (#116) |
| Dogfooding | csd against the real target stack | the homelab host | ❌ host-side (#116) |

## Required test types per change (the per-observer bar)

The tiers above say what *can* be tested; this section says what a change **must**
ship. It exists because the v0.4 `capadd` observer shipped with ~0% coverage at
the `run()`, confidence-rubric, and live layers — not from individual misses but
because the bar was never written down (deep-review #120 retrospective). A new
observer or parser that skips a type below is now a **visible, reviewable
omission**, not a silent gap.

**Every new observer must ship all of these** (all hermetic — runnable in the
sandbox, so there is no excuse to defer them):

| Test type | What it pins | Example |
|---|---|---|
| **Golden / snapshot** | The sidecar JSON shape for the observer's block (run with `-update-golden` only on intentional change) | `TestCapadd_Golden` |
| **`run()`-level CLI table** | `produce*Observation` + **every** `--format` driven end-to-end through `run()`, in each mode (e.g. granted vs default) | `TestRun_CapaddAllFormats` |
| **Confidence-rubric test** | The grade + factors across the states that drive it (clean → moderate, the force-low and two-moderate paths), and any pricing edge (e.g. substitution) | `TestComputeCapaddConfidence` |
| **Live fake-`ig` test** | The spawn → parse → drop-accounting path via the `fakeIGRun` harness (stream + `lost N` → observation + `Dropped`); missing binary → `ExitIGMissing` | `TestObserveCapadd_FakeIG` |
| **Multi-replica** | `--all-matching` populates the disagreement field; `--image` matching >1 without it is `ExitTargetAmbiguous` | `TestCapaddMultiReplica` |
| **Negative / error-path** | The `ExitUsage` flag combinations and the compose-lint contract-gate violation set | `TestRun_CapaddNegativePaths`, `TestCheckCapaddComposeLintContract` |
| **Fuzz** (any new **parser**) | Robustness on hostile input — required whenever a change adds or alters NDJSON/compose parsing | `FuzzAggregateCapadd`, `FuzzCapaddComposePatch` |
| **`-race`** | The observe goroutines / multi-stream merge are data-race-free | `go test -race ./...` (CI gate) |

**Every change** (not just observers): a Medium/Low correctness fix lands with a
regression test that fails before the fix (tab/CRLF/no-newline/anchored-patch
goldens; the `parseIGStderr` oversized-line test; the L10 denied-attempt test are
the worked examples). A new parser adds a fuzz target. Behavior changes update the
golden in the same PR, never silently.

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
runners, which provide a real kernel + `sudo` + docker — enough for `ig`/BPF. Each
smoke uses a **deterministic, hardware-free hard gate** (e.g. the synthetic
exerciser; a `--device /dev/null:/dev/csd-exerciser-dev` mapping for devices; the
exerciser's CHOWN/SETUID/SETGID checks for capadd; a gateway connect + DNS query
for egress). Reference images are informational (they can legitimately observe
zero post-attach events — see `docs/known-deltas.md`).

**Cost-trimmed cadence (2026-06-19):** the per-PR run is **amd64-only,
synthetic-only, 10s** — the deterministic gates fire within ~1-2s of attach
(500ms init-window), so 10s proves attach/parse without the ~6.5 min of a full
30s reference sweep. The **full reference set (30s)** and a **native
`ubuntu-24.04-arm` leg** (proving the eBPF path on arm64, since we ship arm64
artifacts) run on the **every-3-days `schedule` + `workflow_dispatch`**. The
window/scope are job env keyed on `github.event_name` + `matrix.runner`; a
dispatch `duration` input overrides everywhere. Validate a new live lane before
merge by dispatching it on the branch (don't ship an untested CI path). Locally
these need docker + the pinned `ig` + root: `make smoke-wsl2 / smoke-fs /
smoke-device / smoke-capadd` (+ `scripts/smoke_egress.sh`).

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
tracked in **issue #116**. Status:

1. ✅ **Closed-loop harness** (`scripts/closed_loop.sh`) — derive → relaunch with
   the derived config → re-run the workload → assert it still works, then assert a
   tighter config fails. Hardware-free, so it runs on hosted runners *and* a
   self-hosted one. The only test that proves a derived profile is *correct*, not
   just internally consistent — `csd verify` extended to actually apply the config.
2. ✅ **Fuzz the v0.4 parsers** — the hermetic-tier fuzz gap is closed.
3. 🟡 **Hardware-ful device smoke + kernel matrix** — repo side scaffolded
   (`scripts/smoke_device_hw.sh` + `integration-selfhosted.yml`); needs a
   registered runner.
4. ⬜ **Dogfood** against the real stack — host-side.

**Runner trust model (decided, #116): Option A** — a **GitHub self-hosted runner**,
**ephemeral**, triggered **only** by `workflow_dispatch` + `schedule` against
`main` (never `pull_request`), so it runs only trusted, merged code — never
untrusted PR code privileged, and creates no perpetually-pending PR checks.
Registration + host prerequisites: **`docs/self-hosted-runner.md`**. Bring an
ephemeral runner up on demand (desktop or a homelab VM/LXC), trigger
*integration-selfhosted*, tear it down — no always-on box needed.
