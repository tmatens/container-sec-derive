# container-sec-derive

Runtime tool that derives minimum container security config by observing a running container via eBPF (wraps Inspektor Gadget). Go 1.26+, MIT, one-shot CLI. Binary: `csd`. **v0.2.0 released** — v0.1 shipped the capability observer (signed binaries + private GHCR image); v0.2 added the read-only-filesystem + tmpfs observer (`--observe fs`). v0.3 added privileged-mode decomposition (`--observe devices` + `--observe privileged`). v0.4+ observers are planned but unbuilt.

Authoritative design docs — read these before large changes:
- `PLAN.md` — v1 architecture, decisions, success criteria, threat model
- `ROADMAP.md` — post-v1 observers (read_only, privileged decomp, devices, egress, etc.)
- `README.md` — user-facing overview and relationship to compose-lint

## Current status (v0.3.0 released)

**v0.1.0 shipped 2026-06-14** (release run 27483911054, all jobs green): the GitHub Release carries signed static binaries (`linux/amd64`, `linux/arm64`), signed SPDX + CycloneDX SBOMs, and a signed `SHA256SUMS`; the multi-arch container image is published to **private** `ghcr.io/tmatens/container-sec-derive` (`0.1.0`, `0.1`), manifest cosign-signed (key-based, no public Rekor), verified against `cosign.pub`, with SBOM + OpenVEX attestations. Release chain: #70 (Phase B publish) → #73 (pin cosign 2.x — 3.x dropped `--tlog-upload=false`) → #74 (image-SBOM upload flags) → tag `v0.1.0`.

The full v0.1 build order is implemented and merged (PLAN.md §v0.1 build order, milestones 1–4): subprocess `ig run trace_capabilities` → attribution → aggregator → all seven formatters, JSON evidence sidecar, deterministic confidence rubric, `csd verify` (sidecar-vs-sidecar + run mode), entrypoint cross-check, multi-replica aggregation, IG version-pin CI gate, the postgres/caddy/tailscale/synthetic reference workloads with bisected ground truth, WSL2 smoke matrix, live-BPF integration CI, the cosign/SBOM release pipeline, and the container image build + publish (Step 38 Phase A build + Phase B publish/sign/attest). `--fixture <file>` still replays pre-captured NDJSON so the pipeline runs without BPF/ig.

**COI:** the image is published **private**; the only remaining COI-gated act is flipping GHCR package visibility to public (manual, post-clearance) — and at that point switching cosign back to keyless (OIDC + Rekor) is a deliberate, reviewable change.

**v0.2 — read-only filesystem + tmpfs observer (`--observe fs`): SHIPPED as v0.2.0 (2026-06-14).** The second observer joining the four-layer pipeline (don't collapse the layering — see Architecture); design + scope in **issue #77**. Core signal is `trace_open` write-intent opens (no `unlink`/`rename` gadget at the pinned IG → write-intent only; tmpfs size hints deferred). It derives a `read_only: true` + `tmpfs:` recommendation by correlating observed writes against `docker inspect .Mounts` (or `--mounts-fixture`), emits it in **all seven formatters**, and carries its own evidence — additive `writable_paths` + `fs_recommendation` sidecar blocks, an fs-scoped confidence rubric (`computeFSConfidence`), `trace_health`, and multi-replica correlation (`--all-matching` → per-replica mount union + `replica_write_path_disagreement`; ambiguity error for >1 replica otherwise). `isRootfsWrite` drops pseudo-fs (`/proc`,`/sys`,`/dev`) + relative paths so only actionable rootfs writes count. **Sidecar `schema_version` is now 1.1** (additive, omitempty fs fields → a `--observe caps` sidecar is byte-identical; `ToolVersion = 0.2.0`). Live `ig`/`docker` paths are validated only in `integration.yml` (`scripts/smoke_fs.sh` / `make smoke-fs`; the synthetic exerciser's `/csd-exerciser-target` write is the deterministic hard gate, postgres/caddy/tailscale informational — `docs/known-deltas.md` §fs), not locally. **Full per-PR detail is in `CHANGELOG.md`** (#81–#90). CL-0007 needed no compose-lint change — the static rule already ships there; csd only emits the satisfying profile. **v0.3 — privileged-mode decomposition (CL-0002): SHIPPED as v0.3.0 (2026-06-14).** Design + scope in **issue #92**; PRs **#93–#100**. Scoped to **device-decomposition first** per the maintainer; the IG-gadget survey settled that **no pin bump was needed** (latest v0.53.1 adds only `trace_link` over the pinned v0.51.0), so `security_opt`/AppArmor/seccomp is **deferred** (no denial gadget at the pin). Two new observers reuse the v0.2 `trace_open` signal + `fileEvent` attribution: **`--observe devices`** filters opens to non-default `/dev` nodes (`isDeviceOpen` — the complement of `isRootfsWrite`'s `/dev` exclusion, minus the Docker/OCI default device set) and derives the minimum `devices:` grant; **`--observe privileged`** (`privilegedobserve.go`) runs `trace_capabilities` + `trace_open`/dev as **two concurrent `ig` streams** (live; `--fixture` + `--device-fixture` hermetically), merges into a `privileged_decomposition` block (drop `privileged: true` → `cap_add` + `devices`), and grades confidence as the worse of the two observers. Both emit in **all seven formatters**; device multi-replica correlation adds `replica_device_disagreement`. **Sidecar `schema_version` is now 1.2** (additive, omitempty device fields → caps/fs sidecars byte-identical; `ToolVersion = 0.3.0`). Live integration smoke (`scripts/smoke_device.sh`, `make smoke-device`) is **hardware-free**: a `--device /dev/null:/dev/csd-exerciser-dev` mapping is the deterministic gate, and the privileged gate validated the concurrent two-gadget live path on CI. Full per-PR detail in `CHANGELOG.md`. **Next: the ROADMAP §Maturity parity track** (CONTRIBUTING/SECURITY/AGENTS, issue templates, OpenSSF Scorecard, CodeQL, ClusterFuzzLite — CHANGELOG + PR template + `docs/RELEASING.md` landed in #90); then v0.4 (Docker socket usage, CL-0001).

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
events per `docs/known-deltas.md`). A second matrix (`scripts/smoke_fs.sh`,
`make smoke-fs`) exercises the v0.2 `--observe fs` trace_open path; the
synthetic exerciser is its deterministic gate, the reference images
informational. The kretprobe miss-rate measurement
(`scripts/kretprobe_missrate.sh`, `make missrate`) is `workflow_dispatch`-only
(`run_missrate=true`) to conserve minutes. Both jobs post an allowlisted,
secrets-free result comment on the PR. Locally: `make smoke-wsl2`, `make missrate`
(need docker + pinned `ig` + root — see `docs/dev-setup.md`).

## Commit & PR workflow

- One logical change per commit. Imperative subject ≤72 chars. No Conventional Commits prefixes.
- All commits SSH-signed. Verify: `git log --format='%h %G? %s'` — every commit shows `G`.
- All changes via PR, squash-merge to main.
- **Update the docs your change touches in the same PR**, so the entry-point docs never trail `main`: keep the CLAUDE.md status section current, update the PLAN.md build order, tick PLAN.md success-criteria boxes (only with evidence, never on intent), and bump ROADMAP if a phase moved. Don't reference uncommitted/ephemeral files from committed prose.
- **Add a `CHANGELOG.md` `[Unreleased]` entry for any version-visible change** (new observer/formatter/flag, behavior change, schema bump, security fix). Format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — group under `Added`/`Changed`/`Fixed`/`Removed`/`Security`. Pure refactors, test-only, and internal-doc PRs don't need an entry. The release process versions the `[Unreleased]` section; see `docs/RELEASING.md`.

## Dependency pinning

- **GitHub Actions**: SHA-pin every `uses:` (including first-party), tag in trailing comment. Only exception: `uses: ./`.
- **Go runtime deps**: stdlib-first. Any third-party runtime dep requires discussion — this binary runs root-equivalent.
- **Vendored `ig` binary**: pinned to a specific upstream release SHA, cosign-verified at release time (PLAN.md §Supply-chain). No "latest" anywhere in the release path.
- **Docker base images** (when added): digest-pin.

## Publishing

Signed release artifacts only — static binaries (`csd_linux_amd64`, `csd_linux_arm64`) and the container image **`ghcr.io/tmatens/container-sec-derive`** (GHCR; auth via the ephemeral `GITHUB_TOKEN`, no Docker Hub secret). **Cosign signing is key-based with `--tlog-upload=false`** (NOT keyless) — nothing is written to the public Rekor log while the project is unpublished. Needs repo secrets `COSIGN_PRIVATE_KEY` + `COSIGN_PASSWORD` and a committed `cosign.pub` (`cosign generate-key-pair`); verify offline with `cosign verify-blob --key cosign.pub --insecure-ignore-tlog …`. Binaries get detached `<file>.sig`; the image manifest is cosign-signed and carries SBOM + OpenVEX attestations, with a scheduled Docker Scout scan (`scout-scan.yml`) consuming the same VEX. No manual uploads. **COI posture (per maintainer): private publishing is fine; only PUBLIC exposure is gated.** The GHCR image publishes **private** (collaborator-only, private by default) with no public footprint; the sole COI-gated act is flipping the GHCR package visibility to public — done after the COI decision (no in-workflow approval gate). csd ships to GHCR, not Docker Hub like sibling compose-lint, for the private-by-default + no-extra-secret path; dual-publishing compose-lint to GHCR is a possible later follow-up. When the project goes public, switching cosign back to keyless (OIDC + Rekor) is a deliberate, reviewable change.

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
