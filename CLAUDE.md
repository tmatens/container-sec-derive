# container-sec-derive

Runtime tool that derives minimum container security config by observing a running container via eBPF (wraps Inspektor Gadget). Go 1.26+, MIT, one-shot CLI. Binary: `csd`. **v0.1.0 released** (first signed release — signed binaries + private GHCR image; see Current status). **v0.2** (read-only-filesystem observer) is in progress; v0.3+ observers are planned but unbuilt.

Authoritative design docs — read these before large changes:
- `PLAN.md` — v1 architecture, decisions, success criteria, threat model
- `ROADMAP.md` — post-v1 observers (read_only, privileged decomp, devices, egress, etc.)
- `README.md` — user-facing overview and relationship to compose-lint

## Current status (v0.1.0 released)

**v0.1.0 shipped 2026-06-14** (release run 27483911054, all jobs green): the GitHub Release carries signed static binaries (`linux/amd64`, `linux/arm64`), signed SPDX + CycloneDX SBOMs, and a signed `SHA256SUMS`; the multi-arch container image is published to **private** `ghcr.io/tmatens/container-sec-derive` (`0.1.0`, `0.1`), manifest cosign-signed (key-based, no public Rekor), verified against `cosign.pub`, with SBOM + OpenVEX attestations. Release chain: #70 (Phase B publish) → #73 (pin cosign 2.x — 3.x dropped `--tlog-upload=false`) → #74 (image-SBOM upload flags) → tag `v0.1.0`.

The full v0.1 build order is implemented and merged (PLAN.md §v0.1 build order, milestones 1–4): subprocess `ig run trace_capabilities` → attribution → aggregator → all seven formatters, JSON evidence sidecar, deterministic confidence rubric, `csd verify` (sidecar-vs-sidecar + run mode), entrypoint cross-check, multi-replica aggregation, IG version-pin CI gate, the postgres/caddy/tailscale/synthetic reference workloads with bisected ground truth, WSL2 smoke matrix, live-BPF integration CI, the cosign/SBOM release pipeline, and the container image build + publish (Step 38 Phase A build + Phase B publish/sign/attest). `--fixture <file>` still replays pre-captured NDJSON so the pipeline runs without BPF/ig.

**COI:** the image is published **private**; the only remaining COI-gated act is flipping GHCR package visibility to public (manual, post-clearance) — and at that point switching cosign back to keyless (OIDC + Rekor) is a deliberate, reviewable change.

**v0.2 — read-only filesystem + tmpfs observer (in progress).** The second observer (design + scope decisions in **issue #77**; live status in **ROADMAP §v0.2**). Pure, fixture/unit-tested core landed first on `main`: the `trace_open` event model + write-intent classifier + write-path aggregator (`fileevent.go`, #78), the volume-correlation / `read_only`+`tmpfs` decision layer (`fsdecision.go`, #78), and the compose `read_only`/`tmpfs` formatter (`fsformat.go`, #79). Scope: core signal is `trace_open` (no built-in `unlink`/`rename` gadget at the pinned IG version → write-intent opens only; tmpfs size hints deferred). **Live wiring landed** (`fsobserve.go`): an `--observe caps|fs` selector routes through `run()` to `produceFSObservation`, which mirrors the cap path — `observeWrites` runs live `ig run trace_open --paths`, mounts come from `docker inspect .Mounts` (or `--mounts-fixture` for hermetic tests), and `fsToSidecar` joins writes+mounts into a full `*Sidecar`. **Sidecar + confidence landed** (PR-A): the fs observer now produces the canonical evidence artifact — an additive `writable_paths` block (per-path event counts + comm samples + `volume_covered`/`tmpfs_candidate` disposition) and an `fs_recommendation` block, with `trace_health` (ringbuf drops) and an fs-scoped confidence rubric (`computeFSConfidence` — write-event volume as a tmpfs-completeness proxy, drop rate, duration floor, workload presence). The fs fields are `omitempty` so a `--observe caps` sidecar is byte-identical to pre-v0.2. **All seven formatters wired for `fs`**: `compose`, `json`, `docker-run` (`--read-only --tmpfs`), `k8s` (`readOnlyRootFilesystem` + in-memory `emptyDir` mounts), `oci` (`root.readonly` + tmpfs mounts), `compose-patch` (unified diff injecting `read_only`/`tmpfs` into a service — reuses the cap patch's stdlib compose machinery; an empty derived tmpfs set never removes a user's existing block), and `compose-lint-profile` (CL-0007 contribution entry with an fs acceptance contract + `--allow-exploratory`). All honor `--out`/`--workload`. **Next increment:** multi-replica fs correlation under `--image` (live mounts currently require `--container`); then reference ground truth + integration CI. CL-0007 needs no compose-lint changes — the static rule already ships there; csd only emits the satisfying profile. This is the second observer joining the four-layer pipeline — see the Architecture note on not collapsing the layering. (The live `ig`/`docker` paths can only be validated in integration CI, not locally.)

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
