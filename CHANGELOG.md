# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions track the `csd` tool. The evidence-sidecar JSON has its own
`schema_version` (semver-on-schema); schema-affecting changes are called out in
the relevant entry.

## [Unreleased]

The privileged-mode decomposition observer (v0.3, device-decomposition first;
design in issue #92). In progress — landing across several PRs.

### Added

- **`--observe devices`**: a third observer that derives the minimum explicit
  `devices:` grant a `privileged: true` container actually needs, by tracing
  opens (`ig run trace_open --paths`) of non-default `/dev` nodes — everything
  under `/dev` except the Docker/OCI default device set (`/dev/null`, `/dev/zero`,
  `/dev/ptmx`, `/dev/pts/*`, `/dev/shm`, `/dev/mqueue`, …) every container already
  gets. `--observe caps`/`fs` are unchanged. All seven formatters emit device
  output: `json`, `compose` / `docker-run` (`--device` flags), `k8s`
  (device-plugin guidance + `privileged: false` — k8s has no per-device
  SecurityContext grant), `oci` (observed nodes in `annotations`, since
  `linux.devices` needs host-resolved major/minor), `compose-patch` (unified
  diff that sets the service's `devices:` block), and `compose-lint-profile`
  (the CL-0002 contribution entry, `observer: devices`).
- The evidence sidecar gains a `device_paths` block (per-node event counts and
  comm samples) and a `device_recommendation` block (the per-node `devices:`
  list plus conservative derived-capability hints), with a device-scoped
  confidence rubric (no event-count floor — device opens are inherently sparse).
- Multi-replica device correlation under `--image`/`--all-matching`: an
  ambiguity error for more than one replica without `--all-matching`, a
  per-replica device union, and `replica_device_disagreement` fed to confidence
  and the compose-lint contract.
- **`--observe privileged`**: composes the capability and device observers (two
  concurrent `ig` gadget streams live; `--fixture` + `--device-fixture`
  hermetically) and emits the minimum non-privileged equivalent — drop
  `privileged: true`, add the observed `cap_add` + `devices`. The sidecar gains
  a `privileged_decomposition` block; confidence is the worse of the two
  observers' grades, with factors tagged `[caps]`/`[devices]`. `security_opt`
  (AppArmor/seccomp) is out of scope for v0.3 (no denial gadget at the pinned
  IG). `json` and `compose` output land in this increment; the remaining
  formatters follow. Implements **CL-0002**.

### Changed

- Sidecar `schema_version` **1.1 → 1.2** (additive, omitempty device fields; a
  `caps`/`fs` sidecar is byte-identical). `tool_version` → `0.3.0`.

## [0.2.0] - 2026-06-14

The read-only-filesystem + tmpfs observer.

### Added

- **`--observe fs`**: a second observer that derives a `read_only: true` +
  `tmpfs:` recommendation by tracing write-intent opens (`ig run trace_open
  --paths`) and correlating them against the container's mounts. `--observe
  caps` (the default) is unchanged. `--mounts-fixture` supplies mount config
  hermetically for tests/CI.
- All seven formatters emit fs output: `compose`, `json`, `docker-run`
  (`--read-only --tmpfs`), `k8s` (`readOnlyRootFilesystem` + in-memory
  `emptyDir` volumes), `oci` (`root.readonly` + tmpfs mounts), `compose-patch`
  (unified diff), and `compose-lint-profile` (the CL-0007 contribution entry).
- The evidence sidecar gains a `writable_paths` block (per-path event counts,
  comm samples, and `volume_covered`/`tmpfs_candidate` disposition) and an
  `fs_recommendation` block, an fs-scoped confidence rubric, and `trace_health`.
- Multi-replica fs correlation under `--image`/`--all-matching`: an ambiguity
  error for more than one replica without `--all-matching`, a per-replica mount
  union, and `replica_write_path_disagreement` fed to confidence.
- Live integration-CI smoke for the fs observer (`scripts/smoke_fs.sh`,
  `make smoke-fs`) with the synthetic exerciser's `/csd-exerciser-target` write
  as a deterministic hard gate; fs reference ground truth
  (`testdata/synthetic/fs_expected.json`); a `docs/known-deltas.md` §fs section.
- Fuzz targets for the parsers of untrusted subprocess output
  (`fileEvent`/`capEvent` `UnmarshalJSON`, `parseMountDestinations`).

### Changed

- Sidecar `schema_version` 1.0 → **1.1** for the additive, omitempty fs fields.
  A capability (`--observe caps`) sidecar is byte-identical under 1.1.
- `isRootfsWrite` filters kernel pseudo-filesystem writes (`/proc`, `/sys`,
  `/dev`) and unresolved relative paths out of the fs observation, so the
  recommendation only covers actionable container-rootfs writes. (Found by the
  live fs smoke, which recommended tmpfs for `/proc/<pid>/attr/apparmor` before
  the fix.)

## [0.1.0] - 2026-06-14

First signed release — the capability observer.

### Added

- **`csd observe`**: derives the minimum `cap_drop`/`cap_add` set for a running
  container by tracing `cap_capable` via Inspektor Gadget (`ig run
  trace_capabilities`), with cgroup-id attribution, an init-noise filter, and
  multi-replica aggregation (`--image` / `--all-matching`).
- The canonical JSON evidence sidecar (`--out`), a deterministic confidence
  rubric, and seven output formatters (`compose`, `compose-patch`,
  `compose-lint-profile`, `docker-run`, `k8s`, `oci`, `json`).
- `csd verify`: sidecar-vs-sidecar and run-mode self-consistency classification.
- Entrypoint cross-check (`docker inspect` / `docker history`), the IG
  version-pin gate (`ExitSchemaMismatch`), and the postgres/caddy/tailscale/
  synthetic reference workloads with bisected ground truth.
- WSL2 smoke matrix, live-BPF integration CI, and the kretprobe miss-rate
  (capture-deficit) measurement (< 0.1%, measured).
- Release pipeline: signed static `linux/amd64`+`linux/arm64` binaries, signed
  SPDX + CycloneDX SBOMs, a signed `SHA256SUMS`, and a multi-arch container
  image on `ghcr.io/tmatens/container-sec-derive` — cosign-signed (key-based,
  no public Rekor) with SBOM + OpenVEX attestations, built on a digest-pinned,
  cosign-verified vendored `ig`.

[Unreleased]: https://github.com/tmatens/container-sec-derive/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/tmatens/container-sec-derive/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tmatens/container-sec-derive/releases/tag/v0.1.0
