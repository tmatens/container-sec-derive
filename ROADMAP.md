# Roadmap

The architecture in [PLAN.md](PLAN.md) anticipates a multi-observer future. v1 ships exactly one observer (capabilities); each subsequent phase adds an observer to the same framework — same attribution layer, same output schema, additional formatters as needed.

Phases are ordered by *leverage per unit of work*, not by chronology. Real ordering will adapt to user demand and prototype findings.

> **Phase numbers are stable planning IDs, not release versions.** Each `§vX.Y`
> heading is a fixed identifier assigned in the original planning order; releases
> are numbered sequentially as work actually ships, so the two intentionally
> diverge. The device profile (§v0.7) was delivered early in **v0.3.0**, and the
> dangerous-`cap_add` validator (§v0.5) shipped as **v0.4.0** ahead of the
> deferred Docker-socket observer (§v0.4). Don't renumber phases when the order
> changes — it would break the issue/changelog references that cite these IDs;
> each phase records the release that delivered it instead.

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

> **Status: released (v0.3.0; refined in v0.3.1).** Design and scope in **issue #92**. Scoped to **device decomposition first** per the maintainer; the IG-gadget survey settled that **no pin bump was needed** (latest v0.53.1 adds only `trace_link` over the pinned v0.51.0), so the **AppArmor/seccomp `security_opt` half is deferred** — there is no built-in denial gadget at the pin. Delivered: the **`--observe devices`** observer (`isDeviceOpen` — the decomposition complement of v0.2's `isRootfsWrite`, filtering `trace_open` to non-default `/dev` nodes minus the Docker/OCI default device set; `deviceevent.go` + `devdecision.go`), the live pipeline + sidecar `device_paths` / `device_recommendation` blocks (schema bumped 1.1 → **1.2**), a device-scoped confidence rubric (`deviceconfidence.go`, no event-count floor — device opens are sparse), multi-replica correlation (`replica_device_disagreement`), and **all seven formatters**; and the **`--observe privileged`** composition (`privilegedobserve.go`) that runs `trace_capabilities` + `trace_open`(/dev) as two concurrent `ig` streams (or `--fixture` + `--device-fixture` hermetically), merges into a `privileged_decomposition` block (drop `privileged: true` → `cap_add` + `devices`), grades confidence as the worse of the two observers, and emits the decomposition in all seven formats. Hardware-free live integration smoke (`scripts/smoke_device.sh`: a `--device /dev/null:/dev/csd-exerciser-dev` mapping as the deterministic gate; the privileged gate validated the concurrent two-gadget live path on CI). **CL-0002 needs no compose-lint change** — the static `privileged` rule already ships in compose-lint; csd's job is emitting the satisfying decomposed profile. **v0.3.1** then flags the decomposition as **partial**: the AppArmor/seccomp (`security_opt`) dimension stays unobserved (no denial gadget at the pin), now surfaced via a `# WARNING (partial decomposition)` header, `partial`/`security_opt` sidecar fields, and a stderr advisory so the gap can't be acted on silently.

- **Signal:** combine cap observer (v0.1) + device-open observer (`openat()` on `/dev/*`) + AppArmor denial observer + seccomp denial observer.
- **Aggregation:** synthesize the minimum non-privileged equivalent: `cap_add: [...]` + `devices: [...]` + `security_opt: [...]`.
- **Output:** drop `privileged: true`, emit the decomposed config.
- **Compose-lint rule:** **CL-0002**.
- **High value:** turns "your container needs privileged" into "actually it just needs `--device /dev/dri` + `CAP_SYS_NICE`".

---

## v0.4 — Docker socket API usage

> **Status: deferred — signal-blocked (issue #110).** The intended signal (parse
> the HTTP request line on the docker.sock fd) is not exposed by any built-in IG
> gadget at the pinned `v0.51.0` or the current latest `v0.53.1`: `trace_tcp` /
> `tcpdump` are TCP/IP only (docker.sock is `AF_UNIX`), `trace_ssl` is TLS-only
> (it is plaintext HTTP), and `trace_open` misses `connect()`-based socket use.
> Delivering it would require either a custom csd-authored IG gadget — a change
> to the locked "built-in gadgets, subprocess only" posture (PLAN.md Decisions
> 5/7) — or upstream IG support. So it is held, and the **v0.5 dangerous-cap_add
> validator was pulled ahead of it** (shipped in release v0.4.0). Release
> numbering stays sequential; the ROADMAP phase labels are planning order, not
> release tags.

When a container mounts `/var/run/docker.sock`, *which* API endpoints does it actually call? Most socket-mount cases (Traefik, Portainer, Watchtower) only need a small subset; a properly scoped socket-proxy is safer than full socket access.

- **Signal:** eBPF on `connect()` to the docker.sock path + observe HTTP requests on the resulting fd (or trace `read`/`write` and parse the request line).
- **Aggregation:** distinct `(method, path-prefix)` tuples observed.
- **Output:** suggested socket-proxy ACL config (e.g., for `tecnativa/docker-socket-proxy`), or confirms suppression is the only path forward.
- **Compose-lint rule:** **CL-0001**.

---

## v0.5 — Dangerous cap_add validator

> **Status: released (v0.4.0), pulled ahead of the deferred §v0.4 socket
> observer.** Design + scope in **issue #111**. Inverse of v0.1: it validates an
> already-granted dangerous cap against runtime behavior. Delivered the
> **`--observe capadd`** mode, which reuses the `trace_capabilities` signal (the
> per-event `syscall` field is present at the pin — no new gadget, no pin bump)
> and re-aggregates it by syscall-per-cap (`capadd.go`), a curated honest
> knowledge base with finer-grained substitutions (`capadddecision.go` —
> `SYS_ADMIN`+`perf_event_open` → `PERFMON`, `SYS_ADMIN`+`bpf` → `BPF`; honest
> "no finer cap exists" where true), runc/init + denied-check filtering, the
> optional **`--cap-add`** granted-set input that enables unused → removable
> detection and a recommended minimized `cap_add`, the additive
> `capadd_validation` sidecar block (schema bumped 1.2 → **1.3**), a workload-
> coverage-dominant confidence rubric (`capaddconfidence.go` — the unused-cap
> call is the workload-bounded sharp edge, surfaced like `csd verify`'s
> `over_permissioned` WARN), multi-replica disagreement, **all seven formatters**,
> and a hardware-free live smoke (`scripts/smoke_capadd.sh`: the synthetic
> exerciser's deterministic CHOWN/SETUID/SETGID checks gate "used", an unused
> SYS_MODULE gates "removable"). **CL-0011 needs no compose-lint change** — the
> static dangerous-`cap_add` rule already ships there; csd emits the validated
> minimized profile.

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

> **Status: delivered in v0.3.0** as **`--observe devices`**. The device profile
> (which non-default `/dev/*` nodes a container opens → minimum `devices:` grant)
> was the natural complement of the v0.3 privileged decomposition and shipped with
> it; this phase ID is kept for the planning-order reference, not as outstanding
> work. See §v0.3 and `CHANGELOG.md` [0.3.0].

Which `/dev/*` nodes does the container actually open? Hardware acceleration (`/dev/dri`), audio (`/dev/snd`), GPU (`/dev/nvidia*`), USB devices — none of these are derivable statically.

- **Signal:** `openat()` on `/dev/*`.
- **Output:** minimum `devices:` list.
- **Adjacent to v0.3** but useful standalone.

---

## v0.8 — Network egress allowlist

> **Status: SHIPPED as v0.5.0 (2026-06-18) — `--observe egress`.** Design +
> scope in **issue #136**. Runs the pinned ig `trace_tcp` gadget and derives the
> minimum outbound allowlist from the destinations the container actually
> contacted (outbound `connect()` only — `accept`/`close` filtered). Scoped
> **TCP-first** (`trace_tcp` is TCP-only; a UDP/DNS allowlist via `trace_dns` is
> a deferred sibling) and **IP-based** (the resolved IP `connect()` observed, not
> the hostname the app requested — a `trace_dns` hostname correlation is a
> deferred enhancement). Reuses the existing attribution + multi-replica +
> drop-rate machinery; additive `egress_destinations` + `egress_recommendation`
> sidecar block (schema bumped 1.3 → **1.4**); a conservative confidence rubric
> where workload-absence is forced **low** — the egress *inverted risk*: unlike
> caps/devices a too-tight allowlist BLOCKS the app, so an incomplete allowlist
> is a hard failure, surfaced via a non-strippable caveat. Two egress-only
> enforcement formatters — **`--format nftables`** (a default-DROP `inet
> csd_egress` output chain) and **`--format k8s-networkpolicy`** (a NetworkPolicy
> with `ipBlock`/port Egress rules) — alongside `--format json`. Live-validated
> against real `ig` (`scripts/smoke_egress.sh` in `integration.yml`). **Not a
> compose-lint rule** (per below).
>
> **DNS/hostname follow-up — RELEASED in v0.6.0 (issue #159).** Both deferred siblings
> above are unblocked by the same signal: the survey confirmed `trace_dns` exists
> at the pin with the needed fields (`name`, `addresses`, `qr`, `id`, resolver
> endpoint) — **no pin bump**. Landing incrementally: the `trace_dns` event
> parser and the IP→hostname + resolver aggregation are in, and the fixture path
> (`--dns-fixture`) wires per-destination `hostnames` + a `dns_resolvers` block
> into the sidecar (**schema 1.4 → 1.5**, additive) and the nftables /
> NetworkPolicy formatters (UDP resolver rule first + hostname annotations). The
> resolver-in-allowlist is the key correctness fix — a TCP-only default-DROP
> allowlist silently breaks name resolution. The **live two-gadget concurrent
> path** (trace_tcp + trace_dns as concurrent `ig` streams) is in, so a live
> `--observe egress` run derives hostnames + the resolver with no fixture; the
> live trace_dns parse is gated by a DNS leg in `scripts/smoke_egress.sh`. A
> `trace_dns` failure is non-fatal (the IP allowlist is unaffected). Remaining:
> optional hostname-aware enforcement (e.g. Cilium FQDN policies) and DNS-over-TCP.

For users running iptables/nftables egress filtering or Cilium-style network policies, observed outbound destinations form a minimum allowlist.

- **Signal:** eBPF on `connect()` for outbound TCP/UDP; aggregate per `(image, destination_host, port)`.
- **Output:** allowlist in iptables/nftables/k8s NetworkPolicy/Cilium CNP format.
- **Not a compose-lint rule today** but adjacent — could justify a new rule (`CL-XXXX: no egress restrictions`) using this tool as the data source.

---

## Workload coverage & egress-as-data — issue #206 [design settled, unscheduled]

> **Thesis (issue #206):** every observer's output is bounded by what the
> `--workload` exercised, and that coverage gap is today only *caveated*, never
> *measured*. For a security tool, an unmeasured gap ships under-permissive output
> that "looks complete" — and for `egress` (inverted risk) a missed destination
> becomes a default-DROP that breaks the app. Measuring and narrowing coverage is
> where the product's value compounds, versus the aggregation/formatting (the easy
> half). This epic is the consolidated design; the issue thread carries the
> evidence.

**North star: csd derives, the operator enforces.** There is no single portable
way to enforce name-based egress (Cilium `toFQDNs`, an L7 proxy, a host nftables
set — each different, none universal), so csd should not chase enforcement across
runtimes. The egress deliverable is **provenance-tagged destination data**; the
`nftables`/`k8s-networkpolicy`/`toFQDNs`/proxy renders are optional per-context
adapters, and `json` is the canonical output.

**Spike evidence (2026-07-08, issue #206).** A live measurement (real ig
v0.51.0, concurrent `trace_dns`+`trace_tcp`) tested the "resolved-but-not-connected
= coverage gap" signal. **IP-level it is 82% noise** (dual-stack AAAA never dialed
on a no-v6 host; multi-A CDN/LB pools). **Name-level it is clean** — the dual-stack
torture test produced *zero* false positives while genuine resolved-but-never-dialed
names were caught exactly. So the signal is real **only at name granularity**, and
only as a *complement* (it is blind to direct-IP egress — common in homelab).

### The provenance data model

Each egress destination carries:

- `name` + `observed_ips` (the IPs *this container* was told to use, from its own
  `trace_dns` answers) + `ports`;
- **provenance**: `confirmed` (observed connecting) vs `resolved-only` (looked up,
  not dialed this run — the name-level DNS-vs-connect candidate);
- **visibility**: `image-intrinsic` (public-safe) vs `deployment-specific`
  (local-only), computed mechanically (see public-safety below);
- honesty metadata: `observed_ips` are a **point-in-time snapshot** that rots as
  services move — a name-aware enforcer is needed to stay correct.

### Public-profile safety (conservative, fail-safe)

Unlike caps/fs/devices (properties of the *image*), egress destinations are mostly
the operator's *topology* — publishing them leaks network layout and is wrong for
other deployments. So:

1. `egress` is **local-only by default**; full names + snapshot IPs live only in
   the local sidecar (the operator's own data).
2. The `compose-lint-profile` formatter emits **no egress destinations** by default.
3. The only publishable egress artifact is an **opt-in, auto-redacted,
   image-intrinsic public-FQDN advisory** (names not IPs) — "this image contacts
   these external endpoints by design."
4. Redaction is **automatic, never manual**: a destination is `deployment-specific`
   (excluded) if it is a private/reserved IP (RFC-1918, CGNAT `100.64/10`, loopback,
   link-local, ULA) or an internal name (`.lan`/`.local`/`.internal`/`.corp`/`.arpa`,
   any dotless single-label name). Only a public-routable IP / public multi-label
   FQDN is even a candidate, and even then the name is kept and the IP dropped.
5. That advisory still passes the existing human-reviewed contribution PR.
6. **On any ambiguity, classify `deployment-specific`** — the costs are asymmetric
   (a false "private" loses one advisory line; a false "public" leaks topology).

### Staged build (each slice independent, none scheduled)

1. **Egress provenance data model** (json/sidecar): name-level destinations tagged
   `confirmed`/`resolved-only` with the `visibility` scope + snapshot honesty.
   Enforcement renders become adapters over this. Hermetically testable from the
   spike captures.
2. **Public-profile safety**: the local-only default + the auto-redacted opt-in
   advisory + the `visibility` gate on the `compose-lint-profile` formatter.
3. **Generic coverage signals (all observers)**: run-to-run **convergence** (rerun /
   longer window; new behavior still appearing ⇒ incomplete — and it catches the
   direct-IP egress DNS cannot see), and promote steady-state / target-exited-early
   from buried confidence inputs to first-class coverage *outputs*. This is the
   generalization of the v1 entrypoint cross-check (PLAN.md §Workload coverage) and
   subsumes the `probes.yaml` placeholder.
4. **Later / optional**: name-aware enforcement *adapters* (Cilium `toFQDNs`, a
   squid/Envoy proxy allowlist config); a **forgiving, optional** named manifest
   (fuzzy match, warn-never-fail, never the price of entry); `csd record`/replay of
   a long window; hooks to score an existing e2e/load suite's coverage.

### Non-goals

- csd does not own runtime enforcement, and does not auto-widen a default-DROP
  allowlist (DNS candidates are surfaced, promoted only on explicit opt-in).
- No hand-authored exact-IP manifest as the entry point — coverage must be mostly
  auto-derived (DNS-vs-connect at name level, convergence) with any manifest
  optional and forgiving.

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

- ✅ **`govulncheck.yml`** — Go vulnerability scanning with call-graph
  reachability, gating PRs + push + weekly. Works on the private repo (no GHAS
  needed) since it reports to the job log, not the Security tab.
- ✅ **CodeQL** (`codeql.yml`) — Go + GitHub-Actions static analysis, gating
  PRs + push + weekly. Runs in **artifact mode** (`upload: false` → SARIF
  artifact) because csd is a **private repo without GitHub Advanced Security**,
  so code scanning / the Security tab are unavailable. **COI-gated flip:** when
  the repo goes public (or GHAS is enabled), switch `upload: true` + add
  `security-events: write` and alerts land in the Security tab + PRs.
- **OpenSSF Scorecard** (`scorecard.yml`) — **deferred, COI-gated.** Its value
  (the published supply-chain score + SARIF in the Security tab) needs a
  **public** repo; `publish_results` on a private repo would also leak the
  repo's existence (same reason the README badges are static). Add it at the
  public flip alongside the CodeQL `upload` change.
- ✅ **Continuous fuzzing (ClusterFuzzLite)** — v0.2 added Go fuzz *targets*;
  **`cflite-batch.yml` runs all 7 weekly** (batch mode, accumulating corpus in the
  Actions cache, crash→tracked issue), turning one-off seeds into ongoing coverage
  of the `ig`/`docker`/compose parsers. Scoped weekly + batch-only for Actions cost
  (no per-PR `cflite-pr` flow — `ci.yml` already runs the targets CPU-bounded per
  PR). Private-repo posture: no SARIF/Security-tab upload (same as CodeQL's
  artifact mode). Needs the `go-118-fuzz-build` shim in `go.mod` (build-tagged via
  `internal/fuzzdep`, never linked into the binary — #174); base image
  digest-pinned. Includes `FuzzAggregateDNS` (the trace_dns parser — the one schema
  trap we hit).
- ✅ **Close the live-BPF / "meets intent" testing gap** (**issue #116**, closed
  2026-06-17). The hermetic core was already covered; the kernel-facing half is
  now too — real attach/attribution across three real kernels + real hardware
  (`smoke_device_hw`), a **closed-loop derive→apply→re-run proof**
  (`scripts/closed_loop.sh`), v0.4-parser fuzz targets, and an ephemeral
  `[self-hosted, csd]` runner (`integration-selfhosted.yml`, Option A: dispatch/
  schedule on `main` only). Strategy + tier map in **`docs/testing.md`**.

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
