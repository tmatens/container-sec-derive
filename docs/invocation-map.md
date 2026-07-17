# The invocation→requirement map: how configuration decides the minimum profile

**The study (issue #236):** a container's minimum security profile is not a
property of the image. It is a function of **image × invocation × runtime
posture**, bounded by **workload coverage**. This document is the causal map —
which configuration knob moves which requirement, by what mechanism — with
every claim backed by a reproducible drop-test experiment in this repo
(`testdata/drop-test/*.yaml`) or a criteria doc in the
[profile catalog](https://github.com/tmatens/container-security-profiles).

Nothing upstream documents this relationship: `capabilities(7)` says what a
capability *permits*, Docker docs list the *default* grant, and profiling tools
observe or enforce — none map *"run image X with config Y and the minimum
becomes Z."* csd's drop-test producer is the instrument: a study entry is two
derivations differing in one axis, diffed.

How to read the axis sections: **mechanism** (why the knob moves the
requirement), **evidence** (the measured result and its reproducer), **rule**
(what an operator should expect).

---

## Axis A — `user:`: the single biggest capability driver

**Mechanism.** Most official images start as root and drop to a service user
during init. That drop *is* the capability bill: the re-exec needs
`SETUID`/`SETGID`, and the root phase usually chowns/repairs state dirs
(`CHOWN`, `DAC_OVERRIDE`, sometimes `FOWNER`). Setting `user:` skips the root
phase entirely — the process starts pre-dropped, and the startup caps go unused.

**Evidence — the postgres A/B** (everything held equal except `run.user`; same
image `postgres:16`, same `read_only`+`tmpfs` sibling config, same workload +
non-root assert; specs `postgres-caps.yaml` vs `postgres-caps-userset.yaml`):

| invocation | derived capability minimum |
|---|---|
| default (root → `gosu` drop, fresh initdb) | `[CHOWN, DAC_OVERRIDE, SETGID, SETUID]` |
| `user: postgres` | `[]` — all 14 Docker-default caps removable |

Under `user: postgres` the entrypoint never runs its root phase: no `gosu`
re-exec, no chown of the data dir (the declared VOLUME inherits postgres
ownership from the image) or the socket-dir tmpfs (docker's tmpfs default mode
`1777` makes it writable without ownership), and initdb runs directly as
postgres.

**The drop has shapes**, and the shape predicts the bill (taxonomy from the
catalog build-out; each documented in its criteria doc):

- **re-exec drop** (`gosu`/`su-exec`): postgres, mysql, mongo, rabbitmq,
  mariadb, syncthing → `SETUID`+`SETGID` (+chown-class per image).
- **master/worker fork** (apache): httpd, wordpress, nextcloud → same caps, but
  a dropped `SETGID` *keeps serving with root workers* — only a worker-uid
  assert catches it.
- **in-process drop**: mosquitto (refuses to start if it can't drop).
- **non-root by construction**: prometheus, memcached, haproxy, keycloak →
  zero-cap with no `user:` needed.
- **root that needs nothing**: jellyfin, minio → zero-cap but still uid 0
  (harden further with `user:`).

**Rule.** A profile derived under the default invocation is the conservative
superset. Set `user:` and the startup caps become removable — but re-derive,
don't assume: the service user must then be able to *reach* its state (Axis E).

---

## Axis B — dimensions couple: derive each under the siblings' recommendation

**Mechanism.** Profile dimensions are applied as a unit, and one dimension's
recommendation changes another's minimum. A caps minimum derived on a writable
rootfs can be wrong once `read_only: true` is applied, and vice versa.

**Evidence, both directions:**

- **fs → caps** (postgres): on a writable rootfs the caps minimum is
  `[DAC_OVERRIDE, SETGID, SETUID]`; under the profile's own
  `read_only + tmpfs:[/run/postgresql]` it gains **`CHOWN`** — the root-owned
  tmpfs socket dir must be chowned to postgres at startup. Carried by
  `run.read_only`/`run.tmpfs` in `postgres-caps.yaml`.
- **caps → fs** (netdata): the fs derivation must run under the caps
  recommendation (`cap_drop: ALL` + 4 caps), because its correctness predicate
  (per-process metrics) needs `SYS_PTRACE` granted. Carried by `run.cap_add`
  in `netdata-fs.yaml`.

**Rule.** Never mix a dimension derived under permissive defaults into a
combined profile. Derive under the siblings' *recommendation* (not "extra
hardened", not default), then verify the union once.

---

## Axis C — kernel/runtime posture: "removable" can mean "something looser is covering for it"

**Mechanism.** Some capability needs are gated by a kernel knob, not the image.
The canonical case: whether binding a port <1024 needs `NET_BIND_SERVICE`
depends on `net.ipv4.ip_unprivileged_port_start` — Docker defaults it to `0`
(all ports unprivileged), the kernel (and containerd/CRI-O, hence most of
Kubernetes) defaults to `1024`.

**Evidence — the caddy cap × port_start matrix** (measured on a live BPF host,
issue #236 thread):

| `cap_add` | container `port_start` | binds :80? |
|---|---|---|
| `[NET_BIND_SERVICE]` | 0 (Docker default) | yes — via the sysctl (cap unused) |
| none | 0 | yes — via the sysctl |
| `[NET_BIND_SERVICE]` | 1024 (hardened) | yes — via the granted cap |
| none | 1024 | **no** — `bind: permission denied` |

A drop-test under Docker's default finds the cap *removable* — true for that
runtime, but the only thing binding :80 is the blanket sysctl. Drop the cap and
the service breaks the day the posture is tightened (or the compose moves to
k8s). The catalog therefore derives low-port binders under a **pinned**
`run.sysctls: [net.ipv4.ip_unprivileged_port_start=1024]` and records the
posture in `run_config` (profile schema 1.4).

**Three low-port strategies coexist** (each changes what the profile says):
root+cap (traefik, httpd, ntfy), file capabilities on the binary (pihole — and
then `no-new-privileges` is **incompatible**, the catalog's one no-nnp
profile), and unprivileged-port/non-root (haproxy — a non-root process gets
*no* effective caps from `cap_add` under docker at all).

**One posture-independent exception** (worth knowing the shape): base
`caddy:2`'s binary carries the file cap `cap_net_bind_service=ep`, so under
`cap_drop: [ALL]` the **exec itself** fails (`EPERM` before any bind) at *both*
posture 0 and 1024 — a file-capability need, not a bind-time need. And a custom
build's `COPY --from=builder` silently strips that xattr (Docker `COPY` does
not preserve `security.capability`) — harmless for a root+`cap_add` service,
load-bearing for a non-root one.

**Rule.** For port-dependent caps, ask *which posture* the verdict was derived
under (`run_config.sysctls`). "Removable" under posture 0 is not "safe to drop"
— it may mean a loose default is quietly covering for the grant.

---

## Axis D — deployment mode: host namespaces and group grants

**Mechanism.** What a container can *reach* determines what it exercises.
`pid: host` exposes every host process; host mounts expose host state; and a
group membership can substitute for a capability entirely.

**Evidence — netdata as host monitor** (`netdata-caps.yaml`: `pid: host`, host
`/proc`,`/sys`,docker.sock ro-mounts, host network): the minimum includes
`SYS_PTRACE` (apps.plugin runs real-uid = the netdata user; reading *any*
process's `/proc/<pid>/io|fd` needs it — without it every per-process metric
reads 0, not null). A vanilla `docker run netdata` exercises none of that;
the host-monitor invocation is what makes those caps load-bearing.

**Group grant instead of a cap**: access to `/var/run/docker.sock` is decided
by group membership (the socket is `root:docker` 660), not by any capability.
Two ways to get it — the entrypoint's `PGID`-based `groupadd`, or compose
`group_add:` — and the *filesystem* dimension decides which works: under
`read_only: true`, `groupadd` cannot rewrite `/etc/group`, so **`group_add:`
is the only form that survives the hardened profile** (measured in the netdata
fs derivation, catalog criteria doc).

**Rule.** Derive under the deployment mode you ship (`pid:`, `network_mode:`,
host mounts, `group_add:` are all part of `run_config`). A "vanilla-run"
profile applied to a host-monitor deployment is under-permissioned by
construction.

---

## Axis E — data state and mount ownership: fresh vs lived-in

**Mechanism.** Startup work is conditional on the state it finds. A fresh empty
volume triggers init paths (initdb, chown -R, config seeding); a pre-owned,
pre-initialized volume skips them. Ownership matters the same way: a root-owned
fresh dir needs `CHOWN` to become service-owned; a dir that is *already*
service-owned needs nothing.

**Evidence:**

- **valkey (the false-CHOWN lesson):** a `--tmpfs` data-dir stand-in is fresh
  and root-owned, so the entrypoint's chown fails under a CHOWN-less minimum —
  an artifact of staging, not a real requirement, because a prior deploy's
  named volume is already service-owned. The fix is staging fidelity
  (service-owned stand-ins), not adding CHOWN.
- **mysql vs mariadb divergence:** mysql's root-phase `find` must traverse a
  group-denied `/var/lib/mysql-files` → `DAC_OVERRIDE`; mariadb ships `/data`
  already mysql-owned → no CHOWN. Same family, different shipped state,
  different minimum.
- **The inverse blind spot:** a cap derived *removable* against a fresh empty
  dir may be required against pre-existing foreign-owned content (a migration's
  `chown -R`, a restart repairing state). The harness's
  `run.seed_mounts` (foreign-owned content, modes, `from_image` copies) and
  `run.worst_case_named_volumes` exist to stage that worst case deliberately.
- **Declared VOLUMEs auto-mount writable** even under `--read-only` (redis,
  syncthing), while non-VOLUME data dirs (valkey's `/data`) do not — check
  `docker inspect -f '{{.Config.Volumes}}'` before reading an fs verdict.

**Rule.** A minimum is valid for a *data state*, not just an image. Fresh
first-boot is the conservative superset for init-heavy services (postgres);
pre-existing foreign-owned content is the worst case for chown-class caps.
`run_config.mounts` records what the derivation ran against.

---

## Axis F — command, entrypoint, env: a different program is a different profile

**Mechanism.** `command:`/`entrypoint:` overrides change which code runs;
environment variables toggle whole subsystems. The profile follows the code
path, not the image name.

**Evidence:**

- **keycloak `start-dev` vs `start`:** dev mode re-augments the quarkus lib
  directory in place (`ReadOnlyFileSystemException` under read-only); the
  production `start` on an optimized build writes far less. Same image, two
  filesystem profiles.
- **env-triggered root phases:** `PUID`/`PGID` (linuxserver-style images) and
  netdata's `PGID` turn on chown/groupadd work; `POSTGRES_PASSWORD` &co. gate
  whether initdb runs at all. `run_config.env` records **keys only** (never
  values) for exactly this reason.

**Rule.** Any `command:`/`entrypoint:` override, and any env flag that toggles
a subsystem, invalidates a name-matched profile. Re-derive under your override
(deploy-check does this automatically against the real compose file).

---

## Axis G — what bounds every verdict (the out-of-band axes)

Three context axes are not compose fields but bound the answer's validity:

1. **Runtime baseline** — the default cap/seccomp set you drop *from*, the
   LSM (AppArmor content is unobservable to csd), the derive host's kernel
   sysctls (Axis C). Recorded partially via `run_config.security_opt`/`sysctls`;
   see `docs/re-derive-at-deploy.md` for the derive-environment axis.
2. **Architecture** — derivations here are amd64; arch-specific code paths can
   differ.
3. **Workload coverage** — the predicate itself. A drop-test proves the minimum
   for **what the correctness check exercises** (the netdata `SYS_ADMIN`
   lesson: an unexercised feature *with a privilege-free fallback* derives
   removable and is fine; an unexercised feature *without* one breaks later).
   Coverage measurement is issue #206's territory; the catalog's ADR-018
   confidence model carries it as the `coverage` axis.

---

## Principles distilled

1. **Profiles are invocation-relative.** The published minimum is
   `f(image digest × run_config × posture)`; the `run_config` block (profile
   schema 1.2+) is the invocation contract, not decoration.
2. **The default invocation is the conservative superset** — publish that;
   `user:`-set deployments may drop further after re-deriving (Axis A).
3. **Dimensions interact** — derive each under its siblings' recommendation
   and verify the union (Axis B).
4. **Removable ≠ safe to drop** when a looser control is covering for the
   grant (Axis C). State the posture.
5. **Startup ≠ runtime.** Observation misses startup-only caps; drop-test
   covers the full lifetime. Startup work is conditional on data state (Axis E).
6. **Coverage bounds validity** — a verdict is only as good as the features
   the check drove (Axis G, #206).

---

## Operator reference: "re-derive if your compose sets…"

The scan-list a catalog page's hint links to. *(captured)* = the derivation
records this axis in `run_config`; *(gap)* = it does not (yet) — treat
divergence as unverified.

| compose field | expected effect on the profile |
|---|---|
| `image:` (tag/digest drift, `build:`) | different binary → different profile *(captured: pinned digest; `COPY` strips file caps — Axis C)* |
| `command:` / `entrypoint:` | different program → re-derive *(captured)* |
| `environment:` / `env_file:` | feature toggles; PUID/PGID-class vars add chown/groupadd phases *(captured: keys only)* |
| `user:` | startup caps (SETUID/SETGID/chown-class) become removable — the biggest single driver *(captured)* |
| `read_only:` / `tmpfs:` | fs dimension; *induces* caps (root-owned tmpfs → CHOWN) *(captured via run.read_only/tmpfs)* |
| `volumes:` | writable surface + **ownership** + **data state** all move chown-class caps *(mounts captured; ownership/state staged via seed_mounts, else gap)* |
| `network_mode:` / `pid:` | host namespaces expose host state → SYS_PTRACE-class needs *(captured)* |
| `ports:` vs in-container bind | the *bind* (not the mapping) needs NET_BIND_SERVICE — under posture 1024 only *(sysctls captured, schema 1.4)* |
| `sysctls:` | posture-dependent caps (Axis C) *(captured)* |
| `group_add:` | grants socket/device access with **no** cap; the only docker.sock form that survives `read_only` *(gap in run_config)* |
| `cap_add:`/`cap_drop:`/`privileged:` | the baseline the minimum is measured against; decompose `privileged` via `--observe privileged` *(gap)* |
| `security_opt:` | seccomp masks/reveals syscalls; AppArmor unobservable; `no-new-privileges` breaks file-cap images (pihole) *(captured; MAC content unobservable)* |
| `devices:` / `device_cgroup_rules:` | devices dimension; MKNOD/SYS_RAWIO class *(captured)* |
| `ulimits:` | `memlock`→IPC_LOCK, `rtprio`→SYS_NICE *(gap)* |
| `userns_mode:` / `ipc:` / `uts:` | change cap semantics / reachability *(gap)* |
| `healthcheck:` / `depends_on:` / `init:` | change what is *exercised or observed*, not the intrinsic need (coverage, #206) |

---

*Every table row above traces to a spec in `testdata/drop-test/`, a criteria
doc in the catalog, `docs/field-results.md`, or the measured matrices on issue
#236. If a claim can't be re-run from a committed artifact, it doesn't belong
here.*
