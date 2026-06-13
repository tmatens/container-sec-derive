# container-sec-derive

Runtime tool that derives minimum container security config by observing a running container via eBPF (wraps Inspektor Gadget). Go 1.26+, MIT, one-shot CLI. Binary: `csd`. Pre-release — the full v0.1 build order (alpha → beta → rc → release) is implemented and on `main`; v0.1.0 is at the release-cut stage (see Current status). v0.2+ observers are planned but unbuilt.

Authoritative design docs — read these before large changes:
- `PLAN.md` — v1 architecture, decisions, success criteria, threat model
- `ROADMAP.md` — post-v1 observers (read_only, privileged decomp, devices, egress, etc.)
- `README.md` — user-facing overview and relationship to compose-lint

## Current status (v0.1.0 release cut)

The full v0.1 build order is implemented and merged (PLAN.md §v0.1 build order, milestones 1–4): subprocess `ig run trace_capabilities` → attribution → aggregator → all seven formatters, JSON evidence sidecar, deterministic confidence rubric, `csd verify` (sidecar-vs-sidecar + run mode), entrypoint cross-check, multi-replica aggregation, IG version-pin CI gate, the postgres/caddy/tailscale/synthetic reference workloads with bisected ground truth, WSL2 smoke matrix, live-BPF integration CI, the cosign/SBOM release pipeline, and the container image build (Step 38 Phase A — build only, no push). `--fixture <file>` still replays pre-captured NDJSON so the pipeline runs without BPF/ig.

**Remaining for v0.1.0 (both gated, not open engineering):**
- **Step 38 Phase B** — registry publish + cosign-sign the image manifest. Blocked on employer COI clearance.
- **Cut the `v0.1.0` tag** — first real run of `release.yml`.

The **kretprobe miss-rate < 0.1%** criterion is **measured-green** (2026-06-13, `integration.yml` `run_missrate=true`, run 27473114281): capture deficit ≤ 0.1% via the synthetic counting-mode exerciser (the one reference workload that issues an exact, countable cap stream; postgres/caddy observe `[]` post-attach). Harness: `scripts/kretprobe_missrate.sh` / `make missrate`.

Off the v0.1 critical path: issue #32 (`bisect_caps.sh` 1-minimal→stabilization pass).

## Architecture (forward-compat — PLAN.md §Architecture)

Four layers: **Observer → Attribution → Aggregator → Formatter**. v1 ships exactly one observer (`cap_capable`). Future observers (read_only paths, devices, sockets, egress) plug into this same interface. Don't collapse the layering to ship a second observer faster — it is load-bearing for v0.2+.

Confidence rubric (high/moderate/low) is csd's analog of severity. Rubric definition lives in PLAN.md §Confidence scoring — don't restate it elsewhere; update PLAN.md and reference.

## Privilege posture

csd runs with `CAP_BPF` + `CAP_PERFMON` + `--pid=host` + container-runtime socket. Root-equivalent on the host. Every new dep, every new command surface, every formatter, lands under that blast radius. PLAN.md §Tool posture has the full threat model.

## IG integration

Subprocess, not library (Decisions item 5). IG schema is pinned per release via `PINNED_IG_VERSION` / `MIN_IG_VERSION` / `MAX_TESTED_IG_VERSION` plus per-version fixtures under `testdata/ig-versions/<version>/`. Bumping the pin means: add a new version directory, regenerate sample NDJSON, re-run reference-image smoke, commit. Do **not** patch the parser to cope with schema drift across pinned versions.

## Quality checks

`go vet ./...`, `go test ./...`, `go build -o csd .`. All must pass.

Live-BPF CI (`.github/workflows/integration.yml`) gates PRs beyond the unit
suite: a per-PR smoke job runs `scripts/smoke_wsl2.sh` against real containers on
a hosted runner (synthetic fixture is the deterministic gate; the reference
images are informational — they can legitimately observe zero post-attach cap
events per `docs/known-deltas.md`). The kretprobe miss-rate measurement
(`scripts/kretprobe_missrate.sh`, `make missrate`) is `workflow_dispatch`-only
(`run_missrate=true`) to conserve minutes. Both jobs post an allowlisted,
secrets-free result comment on the PR. Locally: `make smoke-wsl2`, `make missrate`
(need docker + pinned `ig` + root — see `docs/dev-setup.md`).

## Commit & PR workflow

- One logical change per commit. Imperative subject ≤72 chars. No Conventional Commits prefixes.
- All commits SSH-signed. Verify: `git log --format='%h %G? %s'` — every commit shows `G`.
- All changes via PR, squash-merge to main.
- **Update the docs your change touches in the same PR**, so the entry-point docs never trail `main`: keep the CLAUDE.md status section current, update the PLAN.md build order, tick PLAN.md success-criteria boxes (only with evidence, never on intent), and bump ROADMAP if a phase moved. Don't reference uncommitted/ephemeral files from committed prose.

## Dependency pinning

- **GitHub Actions**: SHA-pin every `uses:` (including first-party), tag in trailing comment. Only exception: `uses: ./`.
- **Go runtime deps**: stdlib-first. Any third-party runtime dep requires discussion — this binary runs root-equivalent.
- **Vendored `ig` binary**: pinned to a specific upstream release SHA, cosign-verified at release time (PLAN.md §Supply-chain). No "latest" anywhere in the release path.
- **Docker base images** (when added): digest-pin.

## Publishing

Signed release artifacts only — static binaries (`csd_linux_amd64`, `csd_linux_arm64`) and container image (`ghcr.io/tmatens/container-sec-derive`). Cosign keyless via GitHub OIDC. SHA256SUMS (itself cosign-signed) + SBOM (SPDX + CycloneDX) per release. No manual uploads.

## Things to avoid

- No AI authorship attribution (no `Co-Authored-By` for AI, no "Generated by" notices, no "built with AI" badges).
- No runtime deps beyond the Go stdlib without discussion.
- No direct `ig` Go library imports — subprocess only.
- No second observer before v0.1 ships (Decisions item 8).
- No parser workarounds for IG schema drift; bump the pin and regenerate fixtures instead.
- No mutable refs in CI.
- No `cmd | tee log` as the gating command in a CI step — the pipeline's exit
  becomes `tee`'s `0`, so a real failure passes green (pipefail is not reliably
  in effect for `run:` steps). Capture the exit code: `cmd > log 2>&1 && rc=0 || rc=$?; cat log; exit $rc`.
- No private/internal tooling references in a public repo.
- No restating of PLAN.md content here — link to the section and keep CLAUDE.md tight.
