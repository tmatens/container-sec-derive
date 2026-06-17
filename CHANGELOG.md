# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions track the `csd` tool. The evidence-sidecar JSON has its own
`schema_version` (semver-on-schema); schema-affecting changes are called out in
the relevant entry.

## [Unreleased]

## [0.4.0] - 2026-06-17

### Added

- **`--observe capadd`: the dangerous-`cap_add` validator (ROADMAP §v0.5,
  CL-0011).** The inverse of the v0.1 capability observer: instead of deriving
  caps from zero, it takes already-granted dangerous capabilities and validates
  them against runtime behavior. It reuses the `trace_capabilities` signal — the
  per-event `syscall` field present at the pinned IG v0.51.0 — and re-aggregates
  it by syscall-per-cap (no new gadget, no pin bump). For each validated cap it
  reports whether it was **used** (and by which syscalls), an honest advisory
  from a curated knowledge base, any concrete **finer-grained substitute** (e.g.
  `SYS_ADMIN` observed only via `perf_event_open` → `CAP_PERFMON`; via `bpf` →
  `CAP_BPF`), and — when the granted set is supplied via **`--cap-add`** — flags
  caps granted but **never exercised** as removal candidates and synthesizes a
  recommended minimized `cap_add`. Default (no `--cap-add`) reports observed
  usage of the built-in dangerous-cap set. runc/init bring-up checks and denied
  (`capable:false`) checks are filtered so only genuine workload usage counts.
  Emitted in **all seven formatters**; new additive `capadd_validation` sidecar
  block (per-cap findings + syscalls + advice + recommended set); a capadd-scoped
  confidence rubric whose dominant factor is workload coverage (the unused →
  removable call is workload-bounded, the v0.5 analog of `csd verify`'s
  `over_permissioned` WARN); multi-replica disagreement; hermetic `--fixture`
  golden + unit tests; and a hardware-free live-BPF integration smoke
  (`scripts/smoke_capadd.sh`: the synthetic exerciser's deterministic
  CHOWN/SETUID/SETGID checks gate "used", an unused SYS_MODULE gates "removable").
  Schema bumped 1.2 → **1.3** (additive `capadd_validation`; caps/fs/device/
  privileged sidecars stay byte-identical). Design + scope in **issue #111**.

### Changed

- **Sidecar `tool_version` → 0.4.0; `schema_version` → 1.3.** The next release is
  **v0.4.0**, delivering the dangerous-`cap_add` validator. Release numbering
  stays sequential while the ROADMAP §v0.4 Docker-socket observer is **deferred**
  (signal-blocked — no built-in IG gadget captures AF_UNIX/HTTP payloads at the
  pin or latest; tracked in **issue #110**), so v0.4.0 ships the §v0.5 observer
  ahead of it.

## [0.3.1] - 2026-06-16

### Changed

- **`--observe privileged` now flags its decomposition as partial.** The v0.3
  decomposition recovers only the caps + devices dimensions of `privileged: true`;
  the AppArmor/seccomp (`security_opt`) dimension is not observed (no denial
  gadget at the pinned IG). That gap is now surfaced explicitly so a user cannot
  act on "drop `privileged: true`" without seeing it: the `privileged_decomposition`
  JSON block gains `partial` (bool) and `security_opt` (the caveat string) fields,
  every text formatter prints a `# WARNING (partial decomposition): …` header
  (an `org.containersecderive.security-opt` annotation for `oci`, a
  `partial_decomposition: true` derivation note for `compose-lint-profile`), and a
  stderr advisory fires for every format — including `json` and `compose-patch`,
  whose bodies carry no comment. No schema-version bump: the new fields live
  inside the already-1.2 `privileged_decomposition` block, absent on caps/fs runs.

## [0.3.0] - 2026-06-14

The privileged-mode decomposition observer (v0.3): a device-decomposition
observer plus the full `privileged: true` → `cap_add` + `devices` synthesis.
Design in issue #92.

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
  IG). All seven formatters emit the decomposition: `json`, `compose` /
  `docker-run` (drop-privileged header + cap + device flags), `k8s` (one merged
  `securityContext` with `privileged: false` + capabilities, plus device-plugin
  guidance), `oci` (merged `process.capabilities` + device `annotations`),
  `compose-patch` (one diff that removes `privileged: true` and inserts
  `cap_drop`/`cap_add`/`devices`), and `compose-lint-profile` (`observer:
  privileged`, behind the union of the cap + device acceptance contracts).
  Implements **CL-0002**.
- Live integration-CI smoke for the device + privileged observers
  (`scripts/smoke_device.sh`, `make smoke-device`): a hardware-free hard gate
  that runs the synthetic exerciser with a mapped non-default `/dev` node
  (`--device /dev/null:/dev/csd-exerciser-dev`) and asserts both `--observe
  devices` (records the node) and `--observe privileged` (records the node **and**
  caps — proving the concurrent two-gadget live path). The synthetic exerciser
  gained a device-open in its legacy loop (miss-rate counting mode untouched).

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

[Unreleased]: https://github.com/tmatens/container-sec-derive/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/tmatens/container-sec-derive/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/tmatens/container-sec-derive/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/tmatens/container-sec-derive/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tmatens/container-sec-derive/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tmatens/container-sec-derive/releases/tag/v0.1.0
