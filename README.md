# container-sec-derive

[![release](https://img.shields.io/badge/release-v0.3.1-blue)](https://github.com/tmatens/container-sec-derive/releases/tag/v0.3.1)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![signed: cosign](https://img.shields.io/badge/signed-cosign%20key--based-orange?logo=sigstore&logoColor=white)](#verifying-release-artifacts)
[![SBOM](https://img.shields.io/badge/SBOM-SPDX%20%2B%20CycloneDX-informational)](#verifying-release-artifacts)

<!-- Badges are intentionally static: the repo + GHCR package are private while
     the project is unpublished (COI), so dynamic shields (github/v/release,
     package pulls) would render broken or leak existence. Swap to dynamic
     badges when the project goes public. -->

Runtime observation tool that derives the minimum container security configuration an image actually needs by watching it run.

> **Status: v0.3.1 released.** v0.1 delivered capability observation, the evidence sidecar, seven output formatters, `csd verify`, reference-image bisections, the IG version-pin CI gate, the WSL2 smoke matrix, and the cosign release pipeline (SPDX + CycloneDX SBOMs + OpenVEX) on signed static binaries plus a cosign-signed multi-arch GHCR image. **v0.2 added the read-only-filesystem + tmpfs observer** (`--observe fs`). **v0.3 adds privileged-mode decomposition**: a device observer (`--observe devices`) that derives the minimum `devices:` grant from observed opens of non-default `/dev` nodes, and the `--observe privileged` composition that runs the capability and device observers together to replace `privileged: true` with the minimum `cap_add` + `devices` — emitted in all seven formats, with a `privileged_decomposition` evidence block, a combined confidence rubric, and a hardware-free live integration-CI smoke. **v0.3.1** flags that decomposition as **partial** — the AppArmor/seccomp (`security_opt`) dimension of `privileged: true` is not observed (no denial gadget at the pinned IG), surfaced via a `# WARNING (partial decomposition)` header, `partial`/`security_opt` sidecar fields, and a stderr advisory. See [PLAN.md](PLAN.md), [ROADMAP.md](ROADMAP.md) §v0.3, and [the latest release](https://github.com/tmatens/container-sec-derive/releases).

## What it does

Container hardening config (capabilities, read-only filesystem + tmpfs paths, devices, etc.) is hard to derive statically. The conventional answer is trial-and-error: drop a setting, run the container, watch what breaks, add the setting back, repeat. This tool replaces that loop with eBPF observation.

You point it at a running container; it traces the kernel calls relevant to a given security setting; after a recording window, it emits the minimum config that would have satisfied the observed behavior — in your choice of output format (Compose stanza, `docker run` flags, OCI spec, Kubernetes SecurityContext, JSON).

## Audience

Anyone hardening container security on Docker / Podman / OCI-compatible runtimes. Not orchestrator-specific — the engine observes containers, not Compose files. Compose-shaped output is one of several output formatters.

## Relationship to compose-lint

[compose-lint](https://github.com/tmatens/compose-lint) ships **curated profiles** for known images — fast, offline, instant fix guidance. `container-sec-derive` lets users **derive new profiles** for images compose-lint doesn't yet cover, and contribute them back as PRs to the compose-lint catalog. The two tools form a feedback loop:

```
compose-lint catalog ← PRs with derived profiles ← container-sec-derive
       ↓                                                      ↑
  curated fix:                                       run-it-and-see
  guidance                                                    ↑
       ↓                                                      |
  user runs `compose-lint`  → "no profile for image X" → user runs `container-sec-derive` against image X
```

## Container image

Released images are published to the GitHub Container Registry:

- **Package:** [`ghcr.io/tmatens/container-sec-derive`](https://github.com/tmatens/container-sec-derive/pkgs/container/container-sec-derive)
- **Tags:** `0.3.1` and `0.3` (semver, no `v` prefix); multi-arch (`linux/amd64`, `linux/arm64`).

```sh
# The package is private (see the COI note below) — authenticate to GHCR first.
echo "$GITHUB_TOKEN" | docker login ghcr.io -u <your-github-username> --password-stdin

docker pull ghcr.io/tmatens/container-sec-derive:0.3.1
```

The image manifest is cosign-signed (key-based, no public Rekor) and carries an SPDX SBOM + OpenVEX attestation — verify it before use, see [Verifying release artifacts](#verifying-release-artifacts). Running `csd` needs the privileges described under [the tool's own security posture](#a-note-on-the-tools-own-security-posture).

> **Private while unpublished (COI).** The image is pushed **private** (collaborator-only) and signed with no public Rekor entry. The only public/COI-gated step is flipping the GHCR package to public, done after the COI decision — so the package link above resolves for authenticated collaborators, not anonymously.

## Building from source

Build the binary from source:

```sh
git clone https://github.com/tmatens/container-sec-derive
cd container-sec-derive
go build -o csd .
```

Requires Go 1.26+. Live observation needs Inspektor Gadget (`ig`) at the pinned release — see [docs/dev-setup.md](docs/dev-setup.md) for the install steps. The `--fixture` path (replaying pre-captured NDJSON) does not need `ig`, so most local development works without it.

## Quickstart

Replay a pre-captured fixture (no `ig` needed) to see the default Compose output:

```sh
./csd observe --fixture testdata/ig-versions/v0.51.0/sample.ndjson --container postgres-1
```

Or observe a real running container for 30 seconds and emit a Compose stanza plus a JSON evidence sidecar:

```sh
sudo ./csd observe \
  --container my-postgres \
  --duration 30s \
  --workload ./testdata/postgres/workload.sh \
  --out sidecar.json
```

`--workload` records the script that exercised the container; the sidecar's confidence rubric and the `compose-lint-profile` contribution gate both look for it.

## Usage

```
csd [observe] [flags]              # default — derive profile from observation
csd verify [flags]                 # classify an observation against a baseline
```

The `observe` keyword is optional; `csd --container x` and `csd observe --container x` are equivalent.

Choosing an observer:

| Flag | Default | Meaning |
|---|---|---|
| `--observe caps\|fs\|devices\|privileged` | `caps` | `caps` derives the minimum capability set (v0.1). `fs` derives a read-only-filesystem + `tmpfs:` recommendation from write-intent opens (v0.2). `devices` derives the minimum `devices:` grant from opens of non-default `/dev` nodes, and `privileged` composes caps + devices to replace `privileged: true` with the minimum equivalent (v0.3). |
| `--mounts-fixture <file>` | unset | `fs` only: read the container's mount destinations from a `docker inspect .Mounts` JSON file instead of running `docker inspect` (hermetic tests / CI). |

Under `--observe fs`, the same seven `--format` values emit the read-only/tmpfs equivalent (e.g. `compose` → `read_only: true` + `tmpfs:`, `docker-run` → `--read-only --tmpfs`, `k8s` → `readOnlyRootFilesystem` + in-memory volumes). Mount correlation under `--image` inspects each observed replica; live mounts otherwise come from the `--container` target.

> **`--observe privileged` is a *partial* decomposition.** `privileged: true`
> also relaxes AppArmor/seccomp (the `security_opt` dimension), which csd does
> not yet observe (no denial gadget at the pinned IG). The recommendation
> covers only the caps + devices dimensions, so before you drop `privileged: true`
> confirm the workload does not rely on an unconfined AppArmor/seccomp profile.
> csd flags this on every run: a `partial`/`security_opt` field in the
> `privileged_decomposition` JSON, a `# WARNING (partial decomposition): …`
> header in the text formats, and a stderr advisory.

Selecting a target:

| Flag | Meaning |
|---|---|
| `--container <id\|name>` | Single replica by id, name, or id-prefix (≥6 chars). |
| `--image <ref>` | Select replicas by image; errors if more than one matches without `--all-matching`. |
| `--all-matching` | Aggregate across every replica matching `--image` (union profile, with disagreement recorded on the sidecar). |
| `--fixture <file>` | Replay pre-captured NDJSON instead of running `ig`. Skips kernel/BPF entirely. |

Window and output:

| Flag | Default | Meaning |
|---|---|---|
| `--duration` | `30s` | Observation window for live mode. |
| `--init-window-ms` | `500` | Drop events within this many ms of the first matching event (init-noise filter). 0 disables. |
| `--out <path>` | unset | Write canonical JSON evidence sidecar. |
| `--format <name>` | `compose` | Output format on stdout; see below. |
| `--workload <path>` | unset | Path to the script that exercised the container. Recorded on the sidecar; required by the `compose-lint-profile` gate. |

`compose-patch` additionally requires `--compose-in <file> --service <name>`.

## Output formats

`--format` selects what lands on stdout. The sidecar (`--out`) is the same canonical JSON for every format; it is what tooling consumes.

| Format | Output | Use |
|---|---|---|
| `compose` *(default)* | `cap_drop:` / `cap_add:` block | Paste into `docker-compose.yml`. |
| `compose-patch` | Single-hunk unified diff against `--compose-in` | Apply with `git apply` / `patch -p1` to rewrite an existing service's caps in place. |
| `compose-lint-profile` | compose-lint catalog entry | Contribute to compose-lint. Subject to an acceptance contract (see below). |
| `docker-run` | `--cap-drop` / `--cap-add` flags | Drop into a `docker run` invocation. |
| `k8s` | `securityContext.capabilities` snippet | Splice into a Pod / Deployment manifest. |
| `oci` | OCI runtime spec capability arrays | Hand to a runtime configurator. |
| `json` | Canonical sidecar JSON | Same shape as `--out`; pipe to `jq` or downstream tooling. |

## Sidecar

`--out <path>` writes the canonical evidence JSON: derived caps, per-replica breakdown, target metadata (image digest, container ids, replica count), confidence grade with the rubric factors that contributed, init-window suppression count, `trace_health` (events recorded, events dropped, drop rate), and entrypoint cross-check fields. The sidecar is written even when `csd` exits with `ExitDropRateExcessive` (21) — the artifact-with-caveat case — so CI can still see what was captured.

## csd verify

Two modes; both classify a candidate observation against a baseline and exit with one of `0` (consistent), `10` (insufficient — the proposed profile would deny a cap the workload needs), or `11` (over-permissioned — the profile grants caps the workload never used).

**Sidecar-vs-sidecar.** Compare two prior `csd observe` sidecars without re-running:

```sh
csd verify --baseline old.json --observation new.json
```

**Run-mode.** Restart the container under your proposed config, then have `csd` observe it and classify the result against the baseline in one shot:

```sh
csd verify --baseline old.json --container my-postgres --duration 30s --workload ./workload.sh
```

Run-mode accepts the same target / fixture / duration / workload flags as `observe`. It is what you run after applying a derived profile to confirm the profile is internally consistent.

## Contributing a profile to compose-lint

The `compose-lint-profile` formatter emits a contribution-ready entry, but only if the run clears an acceptance contract: image digest pinned, workload provided and readable, `--duration` ≥ 300s, confidence ≥ moderate, no entrypoint coverage warnings, drop rate < 1%, no replica disagreement. Any miss returns `EX_USAGE` (64) so CI catches it.

```sh
sudo ./csd observe \
  --image ghcr.io/example/myapp:1.2.3 \
  --duration 600s \
  --workload ./test/exercise.sh \
  --format compose-lint-profile \
  --out sidecar.json
```

If the run cannot meet the bar (a smoke run, a noisy host), pass `--allow-exploratory` to emit under an `exploratory:` block instead — useful for sharing a draft, not for merging into the catalog.

## Exit codes

CI integrators read these from `$?`. The full table lives in [PLAN.md §Exit codes](PLAN.md); the in-tree source of truth is `exit_codes.go`.

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Unclassified runtime failure. |
| 10 | `csd verify`: profile is insufficient (a needed cap would be denied). |
| 11 | `csd verify`: profile is over-permissioned (caps granted but never used). |
| 21 | `trace_health` drop rate ≥ 10%; profile written but flagged as untrustworthy. |
| 30 | `ig` version mismatch against `PinnedIGVersion`. |
| 31 | `ig` binary missing or not executable. |
| 40 | `--image` matched multiple replicas without `--all-matching`. |
| 64 | Usage error (bad flags, mutually exclusive selectors, contract not met for `compose-lint-profile`, etc.). |

## Documentation

- [CHANGELOG.md](CHANGELOG.md) — notable changes per release ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)).
- [PLAN.md](PLAN.md) — v1 architecture, decisions, success criteria, threat model, exit codes, confidence rubric.
- [ROADMAP.md](ROADMAP.md) — post-v1 observers (read-only, privileged decomp, devices, egress, …) and the maturity-parity track.
- [docs/RELEASING.md](docs/RELEASING.md) — the release checklist (version bumps, changelog, tagging, the signed pipeline).
- [docs/architecture.md](docs/architecture.md) — diagrams of the four-layer pipeline, the three-phase workflow, the workload-coverage cross-checks, and the privilege/supply-chain posture.
- [docs/dev-setup.md](docs/dev-setup.md) — local development prerequisites, installing `ig`, smoke-running `csd observe`, bisecting a new reference image.
- [docs/known-deltas.md](docs/known-deltas.md) — every documented difference between observed cap sets and bisected ground truth, with cause and disposition.
- [docs/wsl2.md](docs/wsl2.md) — WSL2 + Docker Desktop smoke matrix, kernel/BTF caveats, gap-reporting flow.

## v1 scope

**Capability profiles only.** Observe `cap_capable()` checks, attribute per container/image, emit minimum `cap_drop:` / `cap_add:` set. See [PLAN.md](PLAN.md).

## Future scope

Read-only filesystem + tmpfs paths shipped in **v0.2** (`--observe fs`); privileged-mode decomposition and the device profile shipped in **v0.3** (`--observe privileged` / `--observe devices`). Still ahead: Docker socket usage, dangerous-cap validation, host-network necessity, network egress allowlists. See [ROADMAP.md](ROADMAP.md). All future observers slot into the same architecture as v1.

## Out of scope

- **Enforcement.** This tool observes and recommends; it does not enforce policy. (Use AppArmor / seccomp / PSS for that.)
- **Static analysis of images or compose files.** That's compose-lint's job.
- **Build-time / Dockerfile analysis.** Different problem class.
- **Kubernetes-first UX.** K8s output formatter is in scope; K8s-specific deployment isn't a v1 priority. The `--format k8s` formatter exists so derived profiles can be applied to k8s workloads, not because the tool is intended to live as a DaemonSet.
- **Kernels < 5.8, cgroupv1-only hosts, rootless Podman.** See PLAN.md "Runtime requirements" for the full non-goal list.

## A note on the tool's own security posture

`container-sec-derive` needs the very privileges and mounts it later helps you eliminate: `CAP_BPF`, `CAP_PERFMON`, `--pid=host`, and a bind mount of the container-runtime socket. A `:ro` suffix on that bind mount constrains the socket *file*; it does not sandbox the Docker/Podman API. Any process with the socket can create containers, bind-mount `/`, and become root on the host — so treat `csd`'s blast radius accordingly. It is equivalent to running any other privileged BPF + Docker-API tool on the host.

`csd observe` is coded to issue only read calls against the socket. `csd verify` additionally creates a fresh container to re-run the workload under the proposed config, so it exercises container-create authority deliberately. The distinction is in the code path, not the permission grant — both subcommands run with the same mount.

This is not a contradiction with the tool's purpose — `csd` is a one-shot observer, not a long-running service. Run it for the observation window, then stop it. Release artifacts are cosign-signed; verify signatures before use in any environment you care about. See PLAN.md "Tool posture and distribution" for the full threat model and supply-chain controls.

A long-running daemon shape (v2) with these privileges is its own security decision and will not ship without the corresponding review. See ROADMAP.md.

## Verifying release artifacts

Releases publish two static binaries (`csd_linux_amd64`, `csd_linux_arm64`), a `SHA256SUMS` manifest, and a detached cosign signature (`<file>.sig`) per artifact. Signatures are produced by `.github/workflows/release.yml` using **cosign key-based signing with no transparency-log upload** (`--tlog-upload=false`) — so nothing is written to the public Rekor log while the project is unpublished. Verify offline against the committed project public key `cosign.pub`:

```sh
# Per-binary (--insecure-ignore-tlog just asserts "no Rekor entry is expected")
cosign verify-blob \
  --key cosign.pub \
  --insecure-ignore-tlog \
  --signature csd_linux_amd64.sig \
  csd_linux_amd64

# Or verify the manifest first, then check the binary against it
cosign verify-blob \
  --key cosign.pub \
  --insecure-ignore-tlog \
  --signature SHA256SUMS.sig \
  SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

Each release also publishes two SBOMs — `csd.spdx.json` (SPDX 2.3 JSON) and `csd.cyclonedx.json` (CycloneDX JSON) — generated from the source tree at release time and listed in `SHA256SUMS`. Both are signed with the same key, so the same verify command works:

```sh
cosign verify-blob \
  --key cosign.pub \
  --insecure-ignore-tlog \
  --signature csd.spdx.json.sig \
  csd.spdx.json
```

Releases are signed starting with `v0.1.0` (the first signed release); earlier pre-release builds are unsigned.

The container image ships on GitHub Container Registry as **`ghcr.io/tmatens/container-sec-derive`**. The manifest is cosign-signed (same key, no transparency log) and carries SBOM + OpenVEX attestations. Verify the signature and the attestations against `cosign.pub`:

```sh
# Signature
cosign verify \
  --key cosign.pub \
  --insecure-ignore-tlog \
  ghcr.io/tmatens/container-sec-derive:0.3.1

# Attestations (SBOM + OpenVEX)
cosign verify-attestation --type spdxjson \
  --key cosign.pub \
  --insecure-ignore-tlog \
  ghcr.io/tmatens/container-sec-derive:0.3.1

# Vendored ig provenance — IG version, upstream per-arch tarball digests, and
# the cosign-verified pin (predicate sourced from ig-pin/)
cosign verify-attestation \
  --type https://github.com/tmatens/container-sec-derive/attestations/ig-provenance/v1 \
  --key cosign.pub \
  --insecure-ignore-tlog \
  ghcr.io/tmatens/container-sec-derive:0.3.1
```

> **Status:** live since `v0.1.0` (the first signed release); the examples target the current `0.3.1` — substitute the tag you pulled. These commands work against the published image for authenticated collaborators. Per the project's COI posture, **private** publishing is fine — the GHCR image is pushed **private** (collaborator-only) and signed with no public Rekor entry; the only public/COI-gated act is flipping the GHCR package visibility to public, done after the COI decision.

## License

MIT. Matches compose-lint. See [LICENSE](LICENSE).
