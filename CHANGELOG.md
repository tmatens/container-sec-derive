# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions track the `csd` tool. The evidence-sidecar JSON has its own
`schema_version` (semver-on-schema); schema-affecting changes are called out in
the relevant entry.

## [Unreleased]

### Added

- **Egress provenance data model — `egress_destination_intel` sidecar block
  (#206).** A name-centric view of the observed egress that tags each destination
  with **provenance** (`confirmed` — an address was dialed — vs `resolved_only` —
  a name the container looked up via `trace_dns` but never connected to, the
  name-level DNS-vs-connect coverage signal) and **visibility**
  (`image_intrinsic` — a public FQDN/IP that generalizes across deployments — vs
  `deployment_specific` — the operator's own topology, private IPs / internal
  names, which must never reach a public profile). Provenance is computed at
  **name granularity** — a name is `confirmed` if *any* of its resolved addresses
  was dialed — so a multi-address CDN/dual-stack pool where one address connected
  is not a false gap (validated by the #206 measurement spike). This is data
  alongside the allowlist: it **never widens** the enforced
  `egress_recommendation.allowlist` (a `resolved_only` destination is surfaced,
  not auto-added). Additive, omitempty; sidecar `schema_version` bumped **1.5 →
  1.6** (a non-egress sidecar is byte-identical save the version string). First
  slice of the ROADMAP "Workload coverage & egress-as-data" epic.

### Fixed

- **Entrypoint cross-check no longer discards a good `inspect` when `docker
  history` fails (#180).** `inspectEntrypoint` ran `docker inspect` and `docker
  history` as an all-or-nothing pair, so a `history` regression — the kind Docker
  29's containerd image store introduces, where layers can read `<missing>` for
  non-locally-built images — threw away the digest and `Config` that `inspect` had
  already fetched, skipping the argv cap cross-check and the digest pin entirely.
  The two calls are now decoupled: an `inspect` failure is still fatal (nothing is
  usable), but a `history` failure is soft — the argv heuristics and RepoDigest
  promotion still run, and `cross_check_status` degrades to `partial (history
  unavailable): …` instead of a full `unavailable`. Argv-derived coverage warnings
  still force confidence low in the partial case (they come from `inspect`, which
  survived); only the setcap-from-history signals are lost.

- **Self-hosted live-BPF lane self-heals its pinned `ig` and fails loudly when it
  can't (#322).** The `integration-selfhosted` runner lost the pinned `ig` binary
  (a reboot / `/usr/local/bin` wipe), so every live smoke fast-failed with
  `IGMissing(31)` and the lane stayed degraded for weeks. A new
  `scripts/install_pinned_ig.sh` — an idempotent, per-arch installer verified
  against `ig-pin/SHA256SUMS` — now runs at the top of the self-hosted job to
  re-provision `ig` on the next run, and the preflight step **asserts** the pinned
  `ig` is present, hard-failing with one clear line instead of six identical
  downstream failures. The same script replaces the duplicated inline install
  blocks in `integration.yml`, so the hosted and self-hosted lanes can't drift.
- **Flag-parse errors print once, and `-h`/`--help` exits cleanly (#291).** A bad
  flag previously emitted the message twice (the `flag` package's bare line plus a
  usage dump, then `main`'s `csd: ` prefixed line); it now shows the single
  `csd: <err>` line at `EX_USAGE`. `-h`/`--help` now prints usage to stdout and
  exits `0` instead of the `csd: flag: help requested` line at `EX_USAGE`.

### Security

- **Sanitize DNS-derived hostnames before they enter the egress enforcement
  artifacts (#202).** The observed container fully controls the DNS query names it
  emits, and DNS labels permit arbitrary octets on the wire; those names annotate
  the `nftables` / k8s `NetworkPolicy` output as trailing `#` comments. A name
  carrying a newline (or other control byte) could break out of the comment and
  inject an attacker-chosen line into a ruleset the operator applies as root
  (`nft -f`) — e.g. `ip daddr 0.0.0.0/0 accept`, defeating the default-deny
  allowlist. csd now validates each name as a plain hostname (`[A-Za-z0-9_-]`
  labels, RFC 1035 length limits) and drops any that fail, at both boundaries:
  `aggregateDNS` (so csd-produced sidecars are clean) and the formatters (so an
  externally-supplied `--fixture`/`--inspect-fixture` sidecar cannot inject
  either). A dropped name costs only a comment annotation — the IP allowlist
  itself is `trace_tcp`-derived and unaffected.

### Added

- **Docker-29 validation lane — run the live-BPF gates against the containerd
  image store (#180).** A `docker29` `workflow_dispatch` input on the integration
  workflow installs Docker Engine 29 and switches the runner to the containerd
  image store (`scripts/install_docker29.sh`) before the smokes, so the existing
  caps/fs/device/capadd/egress gates all run against the Docker-29 fresh-install
  default — the store that changes `docker history` (the exact path #328 hardened
  to degrade gracefully). Turns the `PLAN.md` "Docker ≥ 20.10" floor into a tested
  **range** rather than a single-version assumption. The installer is idempotent
  and hard-fails if either the version or the store didn't take, so a green run is
  a real attestation; the preflight's `docker-store=` line makes the flip visible
  in the diagnostic report. `workflow_dispatch`-only for now (it mutates the
  runner's engine and costs Actions minutes) — promotable to a monthly cron.

- **Live-BPF preflight now records the Docker version and image store (#180).**
  The hosted and self-hosted integration lanes ran the live smokes against
  whatever Docker the runner shipped, un-pinned and unrecorded — so a smoke
  failure couldn't be tied to a Docker version or image-store change after the
  fact. The preflight now logs `docker=<server-version>`,
  `docker-store=<driver + DriverStatus>`, and — because csd is
  `--runtime`-parameterized (#164) and the lane runs a podman cross-runtime smoke
  whose `inspect`/`history` path is exactly what #180 protects —
  `podman=<client-version>` (all single projected `--format` fields, no
  `docker info`/`inspect` blob, so no env can ride along). The podman line is
  annotated with whether the podman cross-runtime smoke actually ran on that leg
  (it is non-PR + amd64-only), so a recorded `podman=<v>` on a PR leg reads as
  "installed only", never as "podman was tested this run". Makes the Docker 29
  containerd-image-store default visible in the run diagnostics; the store line
  stays Docker-specific by design (the containerd image store has no podman
  analogue). Turns the `PLAN.md` "Docker ≥ 20.10" floor into something a run can
  actually attest to.

- **In-stack (dependent-tier) drop-test derivation (`deps:` + `run.volumes_from` in
  `scripts/drop_test.sh`).** Derives the capability minimum for a service that
  cannot function in isolation — a backup sidecar that needs the app's RCON, an app
  that needs its DB. A `deps:` list brings the target's dependencies up ONCE on a
  shared network (reachable by name, held up across every trial, torn down at the
  end); only the TARGET is recreated per trial with the candidate dropped, and the
  correctness check drives the target's REAL, stack-backed function.
  `run.volumes_from: [<dep>]` shares a dep's volume with the target. A spec with no
  `deps:` is a leaf and runs exactly as before. **Worked example
  (`testdata/drop-test/mc-backup-caps.yaml` + `correctness/mc-backup.sh`):**
  `itzg/mc-backup` with `deps:[minecraft]` + `volumes_from:[minecraft]` — mc-backup
  RCON-flushes the minecraft dep and tars its shared `/data`. The correctness check
  counts the backup's *entries*, not its existence (mc-backup runs as root and can
  create the archive file while archiving nothing), which is the load-bearing point:
  a "file exists" check would pass on an empty backup. **The exact capability
  result is image- and ownership-specific** — it depends on whether the shared
  `/data` is readable by mc-backup's uid — so this spec is a model exercise, not a
  published profile (a catalog profile must be derived against a specific pinned
  image and its actual `/data` ownership).

- **forgejo capabilities drop-test spec + correctness check
  (`testdata/drop-test/forgejo-caps.yaml` + `correctness/forgejo_deploy.sh`).**
  Derives the minimum capability set for `codeberg.org/forgejo/forgejo` (the
  self-hosted Git forge) against its default s6-init invocation on a fresh `/data`
  volume: **cap_drop:ALL + cap_add:[CHOWN, DAC_OVERRIDE, SETGID, SETUID,
  SYS_CHROOT]** — trimming the full Docker default set 14→5. The image runs **two
  root daemons** (`gitea web`, which chowns `/data` then `su-exec`-drops to the git
  user, and `sshd`, whose per-connection privsep child chroots), so the correctness
  check exercises the whole surface: web/API + a real DB-write/repo-create/git-push
  over HTTP + an SSH connection reaching auth. **SYS_CHROOT is the coverage sharp
  edge** — a web-only check reports 200 while git-over-SSH is silently dead. Feeds
  the published catalog profile (`codeberg.org/forgejo/forgejo`, capabilities).
- **Scheduled deploy-check job (`deploy-check.yml` + `scripts/deploy_check.sh` +
  `deploy-check/manifest.yaml`, csd#240).** On the self-hosted `csd` runner, per
  manifest entry, clones a homelab service's **live** compose from Forgejo and
  runs `compose_derive.sh` against it — deriving the capability minimum under the
  real deployed invocation (on the posture-matched host) and diffing it against
  the declared `cap_add`. **Report-only**: per-service verdicts
  (matches / not_minimized / over_permissioned / under_permissioned) land in the
  job summary; the job doesn't fail on a verdict (graduate to enforce by exiting
  on the worst). First manifest covers **netdata**, **homepage**, **caddy**, and
  immich's **postgres** and **redis (valkey)** — all validated end-to-end on the
  matched host. Needs a read-only `FORGEJO_RO_TOKEN` repo secret.
- **`compose_derive.sh` derives services that `build:` a custom image.** The
  bridge builds the service's image and derives against that actual artifact
  (drop_test gains a `no_pull` path + an image-id digest fallback). This matters:
  the homelab **caddy**'s Dockerfile `COPY --from=builder /usr/bin/caddy`
  **strips the base `caddy:2` binary's `cap_net_bind_service=ep` file
  capability**, so the deployed binary execs without the cap and (under Docker's
  default container `ip_unprivileged_port_start=0`) binds :80/:443 without it →
  verdict `over_permissioned, drop [NET_BIND_SERVICE]`. That verdict is
  runtime-posture-bounded, not a clear over-grant: caddy runs as root, so the
  granted cap still binds :80 under a hardened `port_start=1024` (and dropping it
  fails there) — the cap reads removable only because of the loose default sysctl
  (see `docs/re-derive-at-deploy.md`). Unresolved `${VAR}` env values (e.g.
  `${CF_API_TOKEN}`) are replaced
  with a synthetic placeholder so config that validates the field still loads
  without secrets on the derive host. `correctness/caddy_deploy.sh` asserts caddy
  binds a privileged port (LISTEN), robust to the real reverse-proxy vhost config.
- **`compose_derive.sh` reproduces a first-boot data volume, and **immich's
  postgres** joins the manifest.** A service's data-dir bind set from an
  unresolved `${VAR}` (immich's `${DB_DATA_LOCATION}`) is absent on the derive
  host; `drop_test.sh` now gives it a **fresh, foreign-owned dir per trial**, so a
  service that chowns/chmods its data dir on first boot (postgres) exercises those
  startup caps as it would on a real first deploy — instead of falling back to the
  image's pre-owned dir and under-deriving `CHOWN`/`FOWNER`. immich's DB derives
  minimum `[CHOWN, DAC_OVERRIDE, SETGID, SETUID]` → verdict `over_permissioned,
  drop [FOWNER]` (a real, if minor, over-grant: FOWNER isn't exercised even on a
  fresh foreign-owned data dir). `correctness/postgres_deploy.sh` reads the
  service's `POSTGRES_*` credentials back from the container (they may be
  placeholders for a `${VAR}` secret), runs the reference workload, and asserts a
  non-root server uid.
- **immich's redis (valkey) joins deploy-check + the app-tier stack.** The other
  leaf: valkey drops root → uid 999 via `setpriv` (needs `SETUID`/`SETGID`) and
  would chown a foreign data dir (`CHOWN`), but immich declares no volume for it,
  so `CHOWN` is unused → derived minimum `[SETUID, SETGID]`, verdict
  `over_permissioned, drop [CHOWN]`. `correctness/redis_deploy.sh` does a PING +
  SET/GET round-trip and asserts a non-root uid. The app-tier stack now hardens
  **both** leaves (DB drop FOWNER + redis drop CHOWN); immich still ingests +
  serves under both (re-verified).
- **App-tier verification (`scripts/apptier_verify.sh` + `docs/app-tier-verification.md`).**
  The second correctness tier for a multi-container service: the drop-test loop
  derives each container's caps in isolation (caps are composition-independent),
  and this brings up the *whole* stack with the hardening applied and confirms the
  service does its real job. The worked example (`testdata/apptier/immich/`) runs
  immich's **released** stack (server `v2.7.5` + valkey + the custom postgres) with
  the **derived** DB hardening (declared set minus `FOWNER`) and drives immich's
  real REST API — admin sign-up → login → upload a committed fixture → read back →
  search — reusing the upstream project's *fixtures + API* rather than its
  CI-coupled e2e suite ("pull the pieces we need"). Validated on the BPF host: the
  derived hardening PASSES and an over-hardening (drop `SETUID`) correctly FAILS
  (the DB's privilege-drop breaks → immich never comes up). Live only (`make
  apptier-immich`; needs the `docker compose` v2 plugin + a network pull), not a
  per-PR gate.
- **Home Assistant capabilities drop-test spec + correctness check
  (`testdata/drop-test/home_assistant-caps.yaml` +
  `correctness/home_assistant.sh`).** Derives the minimum for
  `ghcr.io/home-assistant/home-assistant` against its default invocation:
  **cap_drop:ALL + cap_add:[DAC_OVERRIDE]** — trimming the full Docker default set
  **14→1** (the deployment sets no cap_drop; its compose comment: "tighten further
  only after verifying HA still boots"). HA runs `python3 -m homeassistant` under
  s6 **as root** — no privilege drop, no chown — so its only cap comes from *where*
  it writes: root creating its DB/`.storage`/logs in a **non-root-owned `/config`**
  bind needs DAC_OVERRIDE. Derived under a fresh non-root-owned `/config` (a
  `${VAR}` mount, faithful to the `./config` bind); against a root-owned config HA
  needs no caps. Correctness = reach the onboarding API + create the owner user (a
  real config write). Scope is HA *core* — integration caps (NET_RAW ping, device
  access, NET_ADMIN) aren't exercised by a base instance. Feeds the published
  catalog profile.
- **mariadb capabilities drop-test spec + correctness check
  (`testdata/drop-test/mariadb-caps.yaml` + `correctness/mariadb.sh`).** Derives the
  minimum for `docker.io/library/mariadb` against its default (root-then-drop)
  invocation: **cap_drop:ALL + cap_add:[SETGID, SETUID]** — trimming the full Docker
  default set **14→2**. The entrypoint re-execs itself as the mysql user via `gosu`
  (SETUID/SETGID); dropping either fails with `failed switching to 'mysql'`. The
  instructive contrast with postgres: **CHOWN and DAC_OVERRIDE are not required by
  default** — the image ships `/var/lib/mysql` owned by mysql, so a docker-managed
  volume inherits it and the entrypoint's `find`-chown is a no-op (and it re-execs
  as mysql early, so writes are as the owner). A foreign-owned bind mount adds
  **CHOWN** only; running as the mysql uid on a pre-owned datadir shrinks it to `[]`.
  Correctness = a query round-trip + a non-root (uid 999) `mariadbd`. Feeds the
  published catalog profile.
- **grafana filesystem drop-test spec + correctness check
  (`testdata/drop-test/grafana-fs.yaml` + `correctness/grafana.sh`).** Derives the
  read-only-filesystem minimum for `docker.io/grafana/grafana` (grafana already runs
  `cap_drop:ALL`, so the value is the filesystem dimension): **read_only:true,
  tmpfs:[]**. Under a read-only rootfs with only the `/var/lib/grafana` data volume
  (persistent: sqlite DB + plugins) writable, grafana serves, reads/writes its DB,
  and runs backend datasource plugins (prometheus/Loki) — `/tmp` drop-tested as
  **not required** for that. Correctness exercises real function (health db-ok +
  dashboard write/read-back + a backend datasource plugin running), not liveness.
  Confidence **moderate**: a writable `/tmp` is used by features outside this
  workload (runtime plugin install, the elasticsearch plugin, rendering/export), so
  the criteria doc records when to add `tmpfs:[/tmp]`. Feeds the published catalog
  profile.
- **loki filesystem drop-test spec + correctness check
  (`testdata/drop-test/loki-fs.yaml` + `correctness/loki.sh`) + a reusable
  distroless sidecar-probe helper (`correctness/lib/sidecar.sh`).** Derives the
  read-only-filesystem minimum for `docker.io/grafana/loki` (already `cap_drop:ALL`
  + non-root): **read_only:true, tmpfs:[]**. Under a read-only rootfs with only its
  `/loki` data dir (persistent: chunks/WAL/index/rules) writable, loki reaches
  ready, ingests a pushed log, and serves it back on query — `/tmp` drop-tested as
  **not required**. loki is **distroless** (no shell/curl), so `docker exec` can't
  probe it; the correctness check uses the new `sidecar.sh` helper, which runs a
  pinned multi-arch curl in a throwaway container sharing the target's network
  namespace (`--network container:<target>`) — reusable by any future distroless
  spec, works for any target network mode, and never touches the target's
  filesystem (no fs-dimension confound). Feeds the published catalog profile.
- **alloy filesystem drop-test spec + correctness check
  (`testdata/drop-test/alloy-fs.yaml` + `correctness/alloy.sh`).** Derives the
  read-only-filesystem minimum for `docker.io/grafana/alloy` (already `cap_drop:ALL`
  + non-root uid 473): **read_only:true, tmpfs:[]** — the first **reuse** of the
  `lib/sidecar.sh` distroless helper. Under a read-only rootfs with only its
  storage.path location writable (image default `--storage.path=/var/lib/alloy/data`,
  a persistent WAL/state dir), alloy reaches `/-/ready` and runs its pipeline (live
  `alloy_*` metrics) — `/tmp` drop-tested as **not required** (a
  `--storage.path=/tmp/alloy` override would instead need `tmpfs:[/tmp]`). The
  writable stand-in mounts at the parent `/var/lib/alloy` (alloy creates the `data`
  subdir itself; a volume at the exact storage.path fails under read_only) with
  `mode=1777`. Feeds the published catalog profile.
- **minecraft capabilities drop-test spec + correctness check
  (`testdata/drop-test/minecraft-caps.yaml` + `correctness/minecraft.sh`).** Derives
  the minimum for `docker.io/itzg/minecraft-server`: **cap_drop:ALL + cap_add:[SETGID,
  SETUID]** — trimming the full Docker default set **14→2** and validating the
  commonly-declared set as already optimal. The entrypoint gosu-drops root→the
  minecraft user (uid 1000); CHOWN/DAC_OVERRIDE are not needed (the image ships
  `/data` owned by 1000, so a docker volume inherits it — same shape as mariadb).
  Derived with a fast `TYPE=VANILLA`/`FLAT` config since the caps are init/privdrop,
  independent of the server flavour. Correctness = the server answers `mc-monitor
  status` as a non-root process. (The catalog profile was later reverted: `itzg/minecraft-server` is `:latest` by design and has no immutable tag to pin — the spec is retained for a future pinned re-derivation.)

### Changed

- **`drop_test.sh` removes each trial's anonymous volumes (`docker rm -f -v`).** An
  image that declares a `VOLUME` (postgres, mariadb, minecraft, …) gets a fresh
  anonymous volume per `docker run`; the cleanup previously used `docker rm -f`
  (no `-v`), so those volumes leaked and accumulated across a run. For a heavy image
  like minecraft (a server jar + generated world per trial) this **exhausted disk
  mid-run and produced spurious "required" verdicts** — a container that can no
  longer write its data dir or download reads as a capability failure (observed: a
  `MKNOD`-dropped trial "failed to download", a `NET_RAW`-dropped trial "unable to
  write eula"). `-v` drops only the container's anonymous volumes (never named or
  bind mounts), so it is safe for every spec and preserves per-trial fresh-volume
  fidelity.

- **Drop-test rejects a non-empty `fixed` (exit 5).** Every granted element must
  be a drop-tested `candidate`. Under leave-one-out a truly-required element is
  always provable as a candidate, so `fixed` never buys test validity — it only
  means "granted, emitted in the minimum, but never tested," and it hides both an
  over-grant (netdata's `SYS_ADMIN` was removable) and a too-weak correctness
  check. When the drop-test can't prove an element needed, the honest fixes are to
  **strengthen the correctness check** (make it a testable candidate) or, for a
  genuine workload-coverage gap, a **criteria-doc caveat + low confidence** — not
  an untested minimum entry. Distinct from `run.*` (`read_only`/`tmpfs`/`user`/
  `mounts`), the invocation/sibling-dimension context that *is* held constant.
  Every existing spec already uses `fixed: []`, so nothing changes but the guard;
  hermetic self-test (`make drop-test-selftest`, in the CI gate).
- **Drop-test reproduces a bind mount's ownership under a numeric `user:`.** When
  a spec (or a real compose, via `compose_derive.sh`) pins a numeric run uid, a
  bind-mounted directory must be owned by that uid for the run to be faithful: on
  a real deployment the service runs *as* the mount's owner (e.g. homepage runs as
  `1000:1000` and owns `./config`), so it needs no capability to use it. A fresh
  git clone owns the source as the cloning user instead, so a container-as-1000
  gets EACCES and never becomes ready. `drop_test.sh` now stages a private copy of
  each such bind and chowns it to the run uid (via the service image as a
  root-in-container helper — no host root, staying sudo-free). Reproducing the
  *ownership* rather than loosening perms is deliberate: a world-writable mount
  owned by the wrong uid would induce a spurious `FOWNER`/`CHOWN` requirement. This
  is what lets **homepage** derive truthfully in deploy-check (verdict: matches —
  as its own config owner it needs no caps). Its correctness check now asserts the
  **dashboard serves 200**, not that `/api/healthcheck` reports "up" (which stays
  "up" even while `/` 500s on an unwritable config — the netdata trap).
- **`compose_derive.sh` skips bind mounts whose source is absent on the derive
  host.** A live compose can bind a target-host-specific file (`/usr/bin/msmtp`,
  a host config path) that can't be reproduced on the runner; these don't gate
  capabilities, so they're skipped with a caveat rather than failing the run. If
  one were actually load-bearing, the baseline correctness check fails and the run
  reports that — never a wrong minimum. Named volumes are kept (docker-managed).

### Fixed

- **Drop-test no longer silently grades the wrong container (port pollution).**
  A `network: host` spec (netdata) pins the service to a fixed host port, so a
  stale/leftover container — or running the drop-test on a host that already
  serves that image — leaves a *foreign* instance answering the correctness check's
  `localhost:19999` queries. `drop_test.sh` removed only its own container name,
  never checked the port was free, and never verified the responder's identity,
  so the correctness check could read the wrong instance and pass (or fail) against it —
  corrupting the derived minimum with no error. Three guards, none change a clean
  derivation's result: (1) an optional `health_port` in the spec makes the
  harness **refuse to start** (exit 4) when that port is already held before it
  launches its own single container; (2) the harness now asserts the container
  actually reached `Running` after `docker run`, surfacing a start failure as an
  explicit `observed` reason instead of an opaque correctness-check failure; (3) the
  netdata correctness check adds an **identity check** — the machine guid the API reports
  (`/api/v1/info` `uid`) must equal the container's own guid file, so a foreign
  netdata answering `:19999` is caught rather than trusted.

### Changed

- **netdata caps re-derived to `[DAC_OVERRIDE, SETUID, SETGID, SYS_PTRACE]`
  (drop only `SYS_ADMIN`), with the correctness check fixed to *detect*
  `SYS_PTRACE`.** They were `fixed` ("observation-confirmed used"). An
  intermediate pass wrongly dropped **both** `SYS_PTRACE` and `SYS_ADMIN` (5→3)
  and REGRESSED production — `apps.plugin` collected zeros for every process's
  per-process io/fd metrics while the health-check still read "healthy". Root
  cause was a correctness-check bug, not a coverage limit: `apps.plugin` runs
  real-uid = the netdata user (setuid gives euid 0, not real uid 0), so it needs
  `CAP_SYS_PTRACE` to read **any** process's `/proc/<pid>/io|fd`; without it, it
  doesn't error — it reports every per-process metric as **0**. The check asserted
  "non-null" data, and `0` is non-null, so it passed on broken collection.
  **Fix:** the check now requires a per-process `fds_open` to be **non-zero**
  (`chart_nonzero`) — dropping `SYS_PTRACE` zeros it and the drop-test correctly
  derives it required. `SYS_ADMIN` stays a candidate and derives removable (no
  `ebpf.plugin`; `ebpf=yes` is a no-op). The `drop_test.sh` header now warns that
  "collects data" must mean non-zero, not merely non-null. No tool/schema change.
- **Renamed the drop-test `predicate` → `correctness` check.** The old name
  described the script's logical form (a true/false function), not its job:
  deciding whether the service still *works* after an element is removed — and,
  crucially, being *stronger* than a liveness/"healthy" check (the netdata trap:
  a container runs healthy as root when the privilege drop fails). Renamed the
  spec field (`predicate:` → `correctness:`), the `testdata/drop-test/predicates/`
  directory (→ `correctness/`), the `$PREDICATE` env var of `compose_derive.sh`
  (→ `$CORRECTNESS`), and the docs. Unrelated uses of "predicate" are untouched:
  the SLSA/in-toto provenance predicate, the bisect oracle, the observer's
  event-filter, and the smoke scripts' pass-condition.
- **Drop-test methodology: `candidate` vs `fixed` clarified in the `drop_test.sh`
  header.** The honest default is that *everything the container is granted is a
  `candidate`* (drop-tested for necessity); `fixed` is justified only when an
  element is a precondition for validly testing the others, **never** by
  "observation showed it used" (observation sees a syscall fire, not that the cap
  gated it — a setuid-root helper makes the call as root regardless).

## [0.7.0] - 2026-07-03

### Fixed

- **A live run that records zero events no longer looks like success (#201).**
  A selector that matched nothing (a typo'd `--container`, a wrong `--image`, a
  window in which the target never ran, or a no-op/broken `ig`) produced a
  fully-formed, authoritative-looking `cap_drop: ALL` profile at exit 0 with no
  stderr — indistinguishable from a container observed to genuinely need nothing.
  A **live** run (fixture replay is exempt) with `events_recorded == 0` now emits
  a stderr warning naming the selector, across the cap-family observers
  (caps/capadd/privileged), so an operator or CI grepping stderr can tell the two
  apart. Zero events can be legitimate (an idle container), so it stays a warning,
  not a failure — the profile still prints. Also closes a `CheckIGVersion`
  fail-open: a successful `ig version` that prints no parseable version (a no-op
  binary) now warns instead of silently passing.
- **Sidecar is chowned back to the invoking user under sudo (#209).** Live mode
  needs root, so `sudo csd observe --out sidecar.json` created the evidence
  `root:root 0600` — unreadable to the human who ran it (and to unprivileged
  downstream: `jq`, the `compose-lint-profile` contribution flow). When
  `SUDO_UID`/`SUDO_GID` are set, the sidecar is now chowned to them after writing,
  preserving the restrictive `0600` mode (only ownership moves). Non-sudo runs are
  untouched; the chown is best-effort and never fails the run.
- **Live digest-pinning now works for every observer (was silently broken).**
  The `compose-lint-profile` contract and the catalog schema require a
  digest-pinned `validated_image` (`…@sha256:…`), but a live `csd observe` run
  never populated `image_digest`: the image name attributed from the ig event
  stream is a bare repository (e.g. `postgres`) with no local `:latest` tag, so
  the `docker inspect` behind digest promotion failed with `exit status 1` and
  the digest was left empty. Only the hermetic `--inspect-fixture` path (tests)
  ever pinned a digest, so this went unnoticed until live validation. Fixed by
  resolving an inspectable reference from the **targeted container's image ID**
  (`docker inspect --format '{{.Image}}'`) before the RepoDigests lookup, via a
  new `caps.PopulateImageDigest` helper that all five compose-security observers
  now call (caps/privileged as a fallback after the entrypoint cross-check;
  fs/devices/capadd directly). Also threads `RuntimeBin` into the device and
  capadd pipeline opts so the lookup honors `--runtime`. Verified end-to-end
  against a live digest-pinned `postgres@sha256:…` container: `--observe fs
  --format compose-lint-profile` now emits `status: validated` and clears
  compose-lint's `scripts/validate_profiles.py` (once its CI appends `ci-smoke`).

### Changed

- **`--format compose-lint-profile` reconciled to the compose-lint catalog
  schema (csd#218, compose-lint#360 step 1).** The formatter now emits the
  canonical `profile.schema.json` (Draft 2020-12) shape compose-lint's
  contribution gate enforces, replacing the earlier flat, bare-short-name
  fragment. Across all five observers (caps/fs/devices/capadd/privileged) the
  output is now an **aggregate-per-image document**: top-level
  `schema_version: "1.0"` (the *catalog* schema version), a normalized `image:`
  field (registry+namespace expanded to Docker defaults, tag/digest stripped —
  `postgres` → `docker.io/library/postgres`, mirroring compose-lint's
  `normalize_repository`), `status: validated|exploratory`, and a `dimensions:`
  map keyed by dimension (`caps → capabilities` with explicit `cap_drop: [ALL]`,
  `fs → filesystem`, `devices → devices`, `capadd → cap_add_validation`,
  `privileged → privileged_decomposition`). Per-dimension `derivation` gains
  `sidecar_schema_version` (was `schema_version`), `observer`, `workload_sha256`
  (sha256 of the committed workload), and `observation_backend {ig_version,
  gadgets: []}`; `validated_image`/`validated_date`/`validated_via` moved inside
  `derivation`. The `--allow-exploratory` path now sets `status: exploratory`
  with a top-level `acceptance_contract_violations:` list instead of the old
  `exploratory:` wrapper. The privileged dimension drops the invalid
  `privileged: false` line for schema-mandated `partial: true` +
  `security_opt_unobserved: true`. **Merge model = decision A** (csd#218 §Open
  decision): each run emits one dimension; the catalog automation unions
  per-observer runs into one profile per image (no `csd merge` subcommand). No
  sidecar `schema_version` change (still 1.5); this is an output-shape change to
  one formatter. Output validated against the real compose-lint
  `profile.schema.json`. Exported `format.ComposeLintKey` (bare-short-name) is
  replaced by `format.ComposeLintImage` (normalized repo ref).

### Added

- **`--runtime docker|podman` flag — rootful podman support (issue #164).**
  The container CLI used for image/mount inspection (`inspect`/`history` in the
  caps observer, `inspect .Mounts` in fs) is now selectable via a new
  `internal/runtime` seam, defaulting to `docker`. `ig` is unaffected (it
  auto-detects its own runtime). docker and podman share the same commands +
  `--format` templates (podman's docker-compatible inspect surface). Validated
  by a live podman smoke (`scripts/smoke_podman.sh`, every-3-days schedule):
  ig attach/attribution under podman + the podman inspect/history/mounts parse,
  green on ubuntu-24.04 + rootful podman. Docker stays the default + only
  *per-PR*-tested runtime; rootless podman / containerd / cri-o unsupported.
  No new runtime dependencies (stdlib only).

## [0.6.0] - 2026-06-18

### Added

- **`--observe egress` DNS/hostname correlation (issue #159), fixture path.**
  The v0.5.0 egress observer was TCP-only and IP-based; this adds the
  `trace_dns` signal as a second source (the survey confirmed the gadget and
  its fields exist at the pin — no pin bump). A new **`--dns-fixture`** flag
  supplies a `trace_dns` NDJSON capture alongside the trace_tcp `--fixture`, and
  the egress sidecar gains two additive, omitempty fields:
  per-destination **`hostnames`** (the names that resolved to each IP, from
  trace_dns response packets) and **`dns_resolvers`** on the recommendation (the
  UDP resolver endpoints — the destinations trace_tcp cannot see, which a
  default-DROP allowlist **must** permit or all name resolution breaks). The
  `nftables` and `k8s-networkpolicy` formatters now emit the UDP resolver allow
  rule (first, before the TCP rules) and annotate each IP rule with its
  hostname(s); `json` carries the structured fields. The egress confidence
  factor reflects whether DNS was observed. A TCP-only egress run (no
  `--dns-fixture`) is byte-identical to before save the schema version.
  **Sidecar `schema_version` is now 1.5** (additive).
- **`--observe egress` live two-gadget path (issue #159).** Live, the egress
  observer now runs `trace_tcp` and `trace_dns` as two concurrent `ig`
  subprocesses for one window (mirroring the privileged observer), so a live
  `--observe egress` run derives hostnames and the DNS resolver automatically —
  no fixture needed. The `trace_tcp` error stays fatal (it owns the allowlist);
  a `trace_dns` error is non-fatal enrichment, surfaced on stderr with the run
  continuing on the IP-only allowlist. The live `trace_dns` attach + parse is
  gated by a new DNS leg in `scripts/smoke_egress.sh`: the workload issues DNS
  queries to its gateway and `dns_resolvers` must contain `<gateway>:53`.

## [0.5.0] - 2026-06-18

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
  compose-security observers. Validated live against real `ig` on a hosted
  runner (`scripts/smoke_egress.sh` in `integration.yml` + the self-hosted
  suite): a container TCP-connects to its docker gateway in a loop and the
  egress observation must contain that `(gateway, port)` — proving the live
  `trace_tcp` parse, not just fixture replay.

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

[Unreleased]: https://github.com/tmatens/container-sec-derive/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/tmatens/container-sec-derive/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/tmatens/container-sec-derive/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/tmatens/container-sec-derive/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/tmatens/container-sec-derive/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/tmatens/container-sec-derive/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/tmatens/container-sec-derive/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/tmatens/container-sec-derive/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tmatens/container-sec-derive/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tmatens/container-sec-derive/releases/tag/v0.1.0
