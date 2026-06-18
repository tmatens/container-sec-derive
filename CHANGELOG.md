# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions track the `csd` tool. The evidence-sidecar JSON has its own
`schema_version` (semver-on-schema); schema-affecting changes are called out in
the relevant entry.

## [Unreleased]

### Added

- **`--observe egress`: the v0.8 network-egress observer (ROADMAP §v0.8, issue
  #136), initial JSON output.** Runs the pinned ig `trace_tcp` gadget and derives
  the minimum outbound allowlist from the destinations the container actually
  contacted (outbound `connect()` only — `accept`/`close` filtered), reusing the
  existing attribution + multi-replica + drop-rate machinery. Emits an additive
  `egress_destinations` (per-destination evidence) + `egress_recommendation`
  (the `(addr, port)` allowlist) sidecar block, with a conservative confidence
  rubric that treats workload absence as forced-low — the egress *inverted risk*:
  unlike caps/devices, a too-tight allowlist BLOCKS the app, so an incomplete
  allowlist is a hard failure, surfaced via a non-strippable caveat. **Sidecar
  `schema_version` is now 1.4** (additive, omitempty egress fields → caps/fs/
  device/capadd sidecars stay byte-identical save for the version string).
  Emits the allowlist as enforcement artifacts via two egress-only formats —
  **`--format nftables`** (a default-DROP `inet csd_egress` output chain with an
  accept rule per destination) and **`--format k8s-networkpolicy`** (a
  NetworkPolicy with an Egress ipBlock/port rule per destination); both lead
  with the non-strippable inverted-risk caveat, IPv4 uses `/32`/`ip daddr` and
  IPv6 `/128`/`ip6 daddr`. These formats are rejected (EX_USAGE) for the
  compose-security observers. The live integration smoke is a follow-on.

## [0.4.1] - 2026-06-17

### Security

- **The evidence sidecar (`--out`) is now written `0600`, not `0666`
  (deep-review L4).** It is security evidence written by a root-equivalent
  process and should not be world- or group-readable.

- **`docker inspect`/`docker history` calls now pass `--` before the
  image/container argument (deep-review L2).** Defense-in-depth (not an injection
  fix — there is no shell): `--` prevents an id/ref beginning with `-` from being
  parsed as a docker flag. Applies to the entrypoint cross-check and the fs
  mount lookup.

- **`compose-patch` refuses tab-indented compose files instead of emitting a
  duplicate-key, insecure patch (deep-review M2).** `leadingSpaces()` counts only
  spaces, so a tab-indented `cap_drop`/`cap_add` block read as column 0 (a
  top-level key); the locator missed it and the patch inserted a *second*
  `cap_drop`, leaving the stale block in place and defeating "drop ALL". YAML
  forbids tabs for indentation, so the patch now errors (naming the offending
  line) and asks the user to re-indent with spaces. Applies to all five patch
  formatters (caps/capadd/fs/devices/privileged).

- **`--observe capadd`: retain denied (`capable:false`) attempts so they can't
  silently weaken a recommendation (deep-review L10).** Denied cap checks were
  dropped outright, so a workload that attempted a *broad* operation (e.g.
  `mount` under `CAP_SYS_ADMIN`) but was denied left no trace — and the validator
  could then recommend finer-substituting or dropping that cap on the strength of
  the held syscalls alone. Denied in-scope attempts are now kept (still **not**
  counted as usage): a denied attempt for a syscall no finer capability covers
  now **suppresses** the finer-grained substitution (the broad cap is kept, with
  a caveat naming the denied attempt), and a granted cap that was *only* ever
  attempted-and-denied is **no longer flagged removable**. A denied attempt for a
  syscall that does map to a finer cap (e.g. `perf_event_open`) does not suppress
  the substitution. No sidecar-schema change (`capadd_validation` shape
  unchanged); recommendations are strictly more conservative.

### Fixed

- **`checkIGVersion` runs `ig version` with a bounded, cancellable context
  (deep-review L1).** It used context-less `exec.Command`, so a hung `ig version`
  ignored the timeout and Ctrl-C; it now uses `exec.CommandContext` with a 10s
  ceiling and honors SIGINT/SIGTERM.

- **The caps aggregator hard-fails on a malformed NDJSON line instead of silently
  skipping it (deep-review L3).** Skipping yielded a *smaller* derived cap set
  with no signal — the dangerous direction (a user could drop a needed cap). It
  now matches the fs/device/capadd aggregators (the pinned ig version emits clean
  one-event-per-line NDJSON, so a parse failure means corrupt input). Blank lines
  are still skipped.

- **`compose-patch` line I/O is now faithful: CRLF, missing-final-newline, and
  >1MB lines (deep-review L5/L6/L8).** The emitter read lines with a
  `bufio.Scanner` capped at 1MB, which (L8) silently dropped a >1MB line *and the
  rest of the file* — so a service after a long line became unpatchable — and
  (L6) stripped `\r`, flipping CRLF files to LF and producing a diff that no
  longer matched the original bytes. `splitComposeLines` now splits on `\n`
  directly (no length cap), records the file's `\r\n`/`\n` convention, and
  re-emits it so CRLF round-trips byte-for-byte. (L5) When the original has no
  trailing newline the diff now carries the `\ No newline at end of file` marker,
  so `git apply` / `patch` accept it. Verified end-to-end with `git apply` for
  both CRLF and newline-less inputs. Applies to all five patch formatters.

- **`compose-patch` refuses to rewrite a YAML-anchored block (deep-review L7).**
  Rewriting a `cap_add: &anchor …` (or an alias `cap_add: *anchor`) would drop
  the anchor definition that aliases elsewhere depend on, or silently expand an
  alias — corrupting the file. The patch now errors when the block it would
  *replace* carries an anchor, alias, or merge key. The check is scoped to the
  rewritten block only, so an unrelated `logging: *shared` in the same service
  does not block a cap patch.

- **`--container` id-prefix matching ≥2 containers no longer silently unions
  them (deep-review M3).** The >1-replica ambiguity guard fired only for
  `--image`; a too-short `--container` id-prefix that matched multiple containers
  fell through and emitted the *union* of their profiles — an over-permissioned
  result forbidden by PLAN.md §Target selection. The guard now covers the
  `--container` prefix path too: it errors with the candidate list
  (`ExitTargetAmbiguous`, 40) and asks for a longer or exact id. An exact
  id/name is unaffected (it resolves to one replica); `--all-matching` remains an
  `--image`-only opt-in. Applies across all observers (caps/fs/devices/capadd).

- **The observe path joins the `ig` stderr-drain goroutine before `cmd.Wait()`
  and kills `ig` on an early aggregate error (deep-review L12/L13).** `cmd.Wait()`
  had been called before the drain goroutine was joined, so a trailing `lost N`
  line could be missed and under-count `EventsDropped`; and an early aggregate
  error left `ig`'s stdout undrained, blocking `cmd.Wait()` for the full
  `--duration`. The drain is now joined before `Wait`, and an early error cancels
  the context so `ig` is killed promptly. (CI also gained `go test -race ./...`.)

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

[Unreleased]: https://github.com/tmatens/container-sec-derive/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/tmatens/container-sec-derive/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/tmatens/container-sec-derive/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/tmatens/container-sec-derive/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/tmatens/container-sec-derive/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tmatens/container-sec-derive/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tmatens/container-sec-derive/releases/tag/v0.1.0
