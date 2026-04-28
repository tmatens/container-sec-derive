# container-sec-derive

Runtime observation tool that derives the minimum container security configuration an image actually needs by watching it run.

> **Status:** v0.1.0 release-work. v0.1 alpha / beta / rc shipped (capability observation, sidecar, seven formatters, `verify`, reference-image bisections, IG version-pin CI gate, WSL2 smoke matrix, cosign keyless release pipeline, SPDX + CycloneDX SBOMs). Container image build + vendored `ig` and full docs walkthrough remain before the v0.1.0 tag. See [PLAN.md](PLAN.md) §v0.1 build order.

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

## Building from source

Pre-v0.1.0 builds are unsigned and not published. Build locally:

```sh
git clone https://github.com/tmatens/container-sec-derive
cd container-sec-derive
go build -o csd .
```

Requires Go 1.22+. Live observation needs Inspektor Gadget (`ig`) at the pinned release — see [docs/dev-setup.md](docs/dev-setup.md) for the install steps. The `--fixture` path (replaying pre-captured NDJSON) does not need `ig`, so most local development works without it.

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

- [PLAN.md](PLAN.md) — v1 architecture, decisions, success criteria, threat model, exit codes, confidence rubric.
- [ROADMAP.md](ROADMAP.md) — post-v1 observers (read-only, privileged decomp, devices, egress, …).
- [docs/architecture.md](docs/architecture.md) — diagrams of the four-layer pipeline, the three-phase workflow, the workload-coverage cross-checks, and the privilege/supply-chain posture.
- [docs/dev-setup.md](docs/dev-setup.md) — local development prerequisites, installing `ig`, smoke-running `csd observe`, bisecting a new reference image.
- [docs/known-deltas.md](docs/known-deltas.md) — every documented difference between observed cap sets and bisected ground truth, with cause and disposition.
- [docs/wsl2.md](docs/wsl2.md) — WSL2 + Docker Desktop smoke matrix, kernel/BTF caveats, gap-reporting flow.

## v1 scope

**Capability profiles only.** Observe `cap_capable()` checks, attribute per container/image, emit minimum `cap_drop:` / `cap_add:` set. See [PLAN.md](PLAN.md).

## Future scope

Read-only filesystem + tmpfs paths, privileged-mode decomposition, Docker socket usage, dangerous-cap validation, host-network necessity, device profiles, network egress allowlists. See [ROADMAP.md](ROADMAP.md). All future observers slot into the same architecture as v1.

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

Releases publish two static binaries (`csd_linux_amd64`, `csd_linux_arm64`), a `SHA256SUMS` manifest, and a Sigstore bundle (`<file>.cosign.bundle`) per artifact. Bundles are produced by `.github/workflows/release.yml` using cosign keyless signing via the GitHub OIDC issuer; each bundle is self-contained (signature + certificate + Rekor inclusion proof) so verification does not need to fetch from the transparency log.

```sh
# Per-binary
cosign verify-blob \
  --bundle csd_linux_amd64.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/tmatens/container-sec-derive/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  csd_linux_amd64

# Or verify the manifest first, then check the binary against it
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/tmatens/container-sec-derive/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

Each release also publishes two SBOMs — `csd.spdx.json` (SPDX 2.3 JSON) and `csd.cyclonedx.json` (CycloneDX JSON) — generated from the source tree at release time and listed in `SHA256SUMS`. Both are cosign-signed under the same identity as the binaries, so the same verify command works:

```sh
cosign verify-blob \
  --bundle csd.spdx.json.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/tmatens/container-sec-derive/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  csd.spdx.json
```

Pre-v0.1.0 builds are unsigned. The first signed release will be `v0.1.0`. The container image (`ghcr.io/tmatens/container-sec-derive`) ships in follow-up release-work; this section will grow `cosign verify` examples for it when it lands. Vendored `ig` provenance is not yet recorded in the SBOMs — that lands alongside the container image step.

## License

MIT. Matches compose-lint. See [LICENSE](LICENSE).
