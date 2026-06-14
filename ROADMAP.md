# Roadmap

The architecture in [PLAN.md](PLAN.md) anticipates a multi-observer future. v1 ships exactly one observer (capabilities); each subsequent phase adds an observer to the same framework — same attribution layer, same output schema, additional formatters as needed.

Phases are ordered by *leverage per unit of work*, not by chronology. Real ordering will adapt to user demand and prototype findings.

---

## v0.1 — Capability profiles [planning]

See [PLAN.md](PLAN.md). Observes `cap_capable()`, emits minimum `cap_drop` / `cap_add`. Compose-lint rule: **CL-0006**.

---

## v0.2 — Read-only filesystem + tmpfs paths

The single highest-value future observer. `read_only: true` is borderline-impossible to derive statically; users currently iterate by hand.

> **Status: released (v0.2.0).** Design and scope decisions in **issue #77**. The IG-gadget survey settled the signal on **`trace_open`** (exposes open flags + symlink-resolved path); there is no built-in `unlink`/`rename` gadget at the pinned IG version, so this cut scopes to write-intent opens (tmpfs size hints deferred). Delivered: the `trace_open` event model + write-intent classifier + write-path aggregator (`fileevent.go`), the volume-correlation / `read_only`+`tmpfs` decision layer (`fsdecision.go`, incl. the `isRootfsWrite` pseudo-fs filter), the **live pipeline** (`fsobserve.go`): the `--observe caps|fs` selector, `observeWrites` (live `ig run trace_open --paths`), `docker inspect .Mounts` acquisition (with `--mounts-fixture` for hermetic tests), and the **canonical sidecar + confidence** (`fsToSidecar` → full `*Sidecar` with additive `writable_paths` + `fs_recommendation` blocks, `trace_health`, fs-scoped `computeFSConfidence`). All seven formatters emit fs output (`compose`, `json`, `docker-run`, `k8s`, `oci`, `compose-patch`, `compose-lint-profile`); multi-replica correlation under `--image`/`--all-matching` (ambiguity error, per-replica mount union, `replica_write_path_disagreement`); and live ground-truth + integration CI (`scripts/smoke_fs.sh` in `integration.yml`, synthetic `/csd-exerciser-target` as a deterministic hard gate — the run that first validated the live path also caught and fixed the pseudo-fs noise). Schema bumped 1.0 → **1.1** (additive fs fields). **CL-0007 needs no compose-lint change** — the static `read_only` rule already ships in compose-lint; csd's job is emitting the satisfying profile.

- **Signal:** eBPF on `openat()` with `O_WRONLY` / `O_CREAT`, plus `unlink`, `rename`, paths outside bind-mounted volumes.
- **Aggregation:** group writes by directory prefix; emit `tmpfs:` entries with size hints (peak observed bytes per path).
- **Output:** `read_only: true` + `tmpfs:` list in compose format; equivalent in other formatters.
- **Compose-lint rule:** **CL-0007**.
- **Foot-gun:** distinguishing intentional volume writes (database files) from incidental writes (cache, runtime state). Requires correlating with the container's volume config.

---

## v0.3 — Privileged-mode decomposition

`privileged: true` conflates many things: all caps + all device access + masked-path bypass + AppArmor unconfined + seccomp unconfined. Most containers tagged `privileged` actually need only a subset.

> **Status: released (v0.3.0).** Design and scope in **issue #92**. Scoped to **device decomposition first** per the maintainer; the IG-gadget survey settled that **no pin bump was needed** (latest v0.53.1 adds only `trace_link` over the pinned v0.51.0), so the **AppArmor/seccomp `security_opt` half is deferred** — there is no built-in denial gadget at the pin. Delivered: the **`--observe devices`** observer (`isDeviceOpen` — the decomposition complement of v0.2's `isRootfsWrite`, filtering `trace_open` to non-default `/dev` nodes minus the Docker/OCI default device set; `deviceevent.go` + `devdecision.go`), the live pipeline + sidecar `device_paths` / `device_recommendation` blocks (schema bumped 1.1 → **1.2**), a device-scoped confidence rubric (`deviceconfidence.go`, no event-count floor — device opens are sparse), multi-replica correlation (`replica_device_disagreement`), and **all seven formatters**; and the **`--observe privileged`** composition (`privilegedobserve.go`) that runs `trace_capabilities` + `trace_open`(/dev) as two concurrent `ig` streams (or `--fixture` + `--device-fixture` hermetically), merges into a `privileged_decomposition` block (drop `privileged: true` → `cap_add` + `devices`), grades confidence as the worse of the two observers, and emits the decomposition in all seven formats. Hardware-free live integration smoke (`scripts/smoke_device.sh`: a `--device /dev/null:/dev/csd-exerciser-dev` mapping as the deterministic gate; the privileged gate validated the concurrent two-gadget live path on CI). **CL-0002 needs no compose-lint change** — the static `privileged` rule already ships in compose-lint; csd's job is emitting the satisfying decomposed profile.

- **Signal:** combine cap observer (v0.1) + device-open observer (`openat()` on `/dev/*`) + AppArmor denial observer + seccomp denial observer.
- **Aggregation:** synthesize the minimum non-privileged equivalent: `cap_add: [...]` + `devices: [...]` + `security_opt: [...]`.
- **Output:** drop `privileged: true`, emit the decomposed config.
- **Compose-lint rule:** **CL-0002**.
- **High value:** turns "your container needs privileged" into "actually it just needs `--device /dev/dri` + `CAP_SYS_NICE`".

---

## v0.4 — Docker socket API usage

When a container mounts `/var/run/docker.sock`, *which* API endpoints does it actually call? Most socket-mount cases (Traefik, Portainer, Watchtower) only need a small subset; a properly scoped socket-proxy is safer than full socket access.

- **Signal:** eBPF on `connect()` to the docker.sock path + observe HTTP requests on the resulting fd (or trace `read`/`write` and parse the request line).
- **Aggregation:** distinct `(method, path-prefix)` tuples observed.
- **Output:** suggested socket-proxy ACL config (e.g., for `tecnativa/docker-socket-proxy`), or confirms suppression is the only path forward.
- **Compose-lint rule:** **CL-0001**.

---

## v0.5 — Dangerous cap_add validator

Inverse of v0.1. When `cap_add: [SYS_ADMIN]` (or another dangerous cap) is set, observe which syscalls actually invoked it. Often the dangerous cap was a shotgun fix for a problem solvable with a finer-grained cap.

- **Signal:** correlate `cap_capable` events for the dangerous cap with the calling syscall.
- **Output:** "your SYS_ADMIN was only used for `mount()` — switch to user namespaces and a more specific cap" (with reference docs).
- **Compose-lint rule:** **CL-0011**.

---

## v0.6 — Host network necessity

Validate or refute the choice of `network_mode: host`. Most legitimate cases involve DHCP, multicast, or raw sockets — observable behaviors, not opaque needs.

- **Signal:** detect DHCP client packets, multicast joins, raw socket creation.
- **Output:** confirm legitimate host-network need with evidence, or suggest switching to a user-defined bridge.
- **Compose-lint rule:** **CL-0008**.

---

## v0.7 — Device profile

Which `/dev/*` nodes does the container actually open? Hardware acceleration (`/dev/dri`), audio (`/dev/snd`), GPU (`/dev/nvidia*`), USB devices — none of these are derivable statically.

- **Signal:** `openat()` on `/dev/*`.
- **Output:** minimum `devices:` list.
- **Adjacent to v0.3** but useful standalone.

---

## v0.8 — Network egress allowlist

For users running iptables/nftables egress filtering or Cilium-style network policies, observed outbound destinations form a minimum allowlist.

- **Signal:** eBPF on `connect()` for outbound TCP/UDP; aggregate per `(image, destination_host, port)`.
- **Output:** allowlist in iptables/nftables/k8s NetworkPolicy/Cilium CNP format.
- **Not a compose-lint rule today** but adjacent — could justify a new rule (`CL-XXXX: no egress restrictions`) using this tool as the data source.

---

## Stretch — beyond the named rules

- **Resource baselines.** Observe peak memory / CPU usage; emit `mem_limit:` / `cpus:` recommendations. Could justify a new compose-lint rule.
- **Seccomp profile generation.** Same shape as caps but for syscalls. **Explicitly defer** — this is solved by `oci-seccomp-bpf-hook` and Inspektor Gadget's `advise seccomp-profile`. We integrate or link, we don't reinvent.
- **Process tree audit.** What binaries actually exec inside the container? Useful for catching multi-process containers and entrypoint surprises.
- **File-read profiles.** Paths the container reads from (vs writes — covered by v0.2). Useful for designing volume mounts.
- **LSM-BPF migration for capability observation.** Replace IG's kprobe + kretprobe pair with a single `SEC("lsm/capable")` BPF-LSM hook. One hook, native verdict semantic (LSM hooks return the access decision directly), no per-pid scratch map. Kernel ≥ 5.7 with `CONFIG_BPF_LSM=y`. No OSS tool currently ships this for capability observability — would be a clean upstream contribution to IG when distro support justifies dropping the kretprobe path. Tracking issue / target kernel floor TBD.

---

## Upstream contribution opportunities

Independent of our own roadmap — places where work we'd do for ourselves also benefits the wider OSS ecosystem.

- **Tracee `CapCapableRet` event** — Tracee's `cap_capable` event is entry-only (kprobe), while the same repo wires kretprobe pairs for `vfs_write` and other events. Adding a `CapCapableRet` sibling would expose the granted/denied verdict and make Tracee a viable runtime for tools like ours. Estimated as a small, idiomatic upstream PR (~80 lines BPF + Go event registration, mirroring existing kretprobe patterns). Worth contributing even though we don't use Tracee — broadens the ecosystem.
- **IG `advise capabilities` gadget** — IG has `advise seccomp-profile` but no `advise capabilities` sibling. A narrow upstream PR modeled on the seccomp gadget — aggregate `trace_capabilities` events, emit a cap list, support a k8s-resource output mode — is a plausible contribution *once v1 ships*. Not the full `csd` aggregator (seven formatters, `verify` with self-consistency semantics, confidence rubric, compose-lint contract — all product, not infrastructure) and not a v1 path. See PLAN.md Decisions item 7 for the locked framing: `csd` ships against pinned IG releases and does not block on upstream. Pattern could repeat for v0.2+ (`advise tmpfs-paths`, `advise device-list`) — same split.
- **bcc `libbpf-tools/capable` userspace surfacing** — the BPF object already captures the kretprobe verdict; the userspace `capable.c` doesn't print it. Small UX patch to surface "granted" vs "denied" in the existing tool.

---

## Maturity — parity with compose-lint

`csd` should reach the same project maturity as its sibling **compose-lint** (a
mature, security-focused OSS repo) as it approaches end state. The engineering
infrastructure is already at parity — SHA-pinned CI, a signed multi-arch release
(cosign + SPDX/CycloneDX SBOMs + OpenVEX), digest-pinned + cosign-verified
vendored `ig`, Renovate, a `.vex` directory, live-BPF integration CI, and (as of
v0.2) fuzz targets. The gaps are in **community, governance, process, and
security-automation surface**. Tracked below; none block an observer release,
but together they are the difference between "works" and "mature."

**Process & docs (started v0.2):**

- ✅ **`CHANGELOG.md`** (Keep a Changelog) + a per-PR `[Unreleased]` convention.
- ✅ **`docs/RELEASING.md`** release checklist and **`.github/pull_request_template.md`**.
- ✅ **`CONTRIBUTING.md`** — the contribution bar (signed + DCO commits,
  stdlib-only runtime deps, the four-layer observer contract, ground-truth +
  test expectations, no-AI-attribution), extracted from `CLAUDE.md`.
- ✅ **`.github/SECURITY.md`** — vulnerability-disclosure policy, scoped to the
  root-equivalent posture and the cosign/SBOM/OpenVEX supply chain.
- ✅ **`AGENTS.md`** — the agent-contribution guide (csd is agent-developed).
- ✅ **`.github/ISSUE_TEMPLATE/`** (bug / feature / new-observer-proposal +
  `config.yml`), **`.github/CODEOWNERS`**, **`.github/CODE_OF_CONDUCT.md`**
  (Contributor Covenant 2.1), and **`GOVERNANCE.md` / `MAINTAINERS.md`**
  mirroring compose-lint's set.
- **`release-prep.yml`** — automate the `[Unreleased]` → `[X.Y.Z]` changelog
  rename + version bumps + release PR (compose-lint has this; csd does it by
  hand per `docs/RELEASING.md`).

**Security automation:**

- **OpenSSF Scorecard** workflow (`scorecard.yml`) — a measurable, public
  supply-chain posture score, the same signal compose-lint publishes.
- **CodeQL** (`codeql.yml`) — Go static analysis on PRs (csd is pure Go;
  CodeQL covers it).
- **Continuous fuzzing (ClusterFuzzLite)** — v0.2 added Go fuzz *targets*; wiring
  them into a `cflite-pr` / `cflite-batch` flow (as compose-lint does) turns
  one-off seeds into ongoing coverage of the `ig`/`docker` output parsers.

## Out of scope

- **Enforcement.** This tool only observes and recommends. Use AppArmor / seccomp / Pod Security Standards for runtime enforcement. We may *generate* enforcement artifacts (k8s SecurityContext, AppArmor profiles) but do not apply them.
- **Static analysis of images or compose files.** That's compose-lint's job. We assume the container is running.
- **Build-time / Dockerfile analysis.** Different problem class — best handled by `hadolint`, `dockerfile-utils`, etc.
- **Long-running daemon as v1.** The "leave it on the host for a week" service shape is desirable but doubles the surface area (persistence, restart handling, metrics endpoint, security review of the always-on agent). v1 ships as a one-shot CLI; daemon shape is revisited in v2 if there's pull.
- **Cross-host aggregation.** Multi-host observation, fleet-wide profile derivation, central policy generation — all interesting, all out of scope until there's evidence of demand.

---

## Cross-reference: compose-lint rule coverage

| compose-lint rule | container-sec-derive observer | Phase |
|---|---|---|
| CL-0001 (docker socket mount) | Socket API usage | v0.4 |
| CL-0002 (privileged) | Privileged decomposition | v0.3 |
| CL-0003 (no-new-privileges) | — universal, no observation needed | n/a |
| CL-0005 (unbound port) | — network policy decision, not observable | n/a |
| CL-0006 (cap_drop) | Capability profile | **v0.1** |
| CL-0007 (read_only) | Writable path detection | v0.2 |
| CL-0008 (host network) | Host network necessity | v0.6 |
| CL-0010 (host namespace) | (covered partially by v0.3) | v0.3 |
| CL-0011 (dangerous cap_add) | Dangerous cap validator | v0.5 |
| CL-0016 (secrets) | — static catches it | n/a |

A profile contributed by container-sec-derive should cite its observer version + observed image digest + workload script in the compose-lint catalog entry. The contribution flow itself is part of v0.1 success criteria.
