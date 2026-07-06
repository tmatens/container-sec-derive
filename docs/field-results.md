# Field results — real-image profiling with csd

Durable record of `container-sec-derive` runs against real, digest-pinned
container images on a live BPF host. Each entry is reproducible from the image
reference alone. These are the worked examples behind the capability/hardening
narrative — written up for a general audience in
[articles/finding-minimum-capabilities.md](articles/finding-minimum-capabilities.md)
— and the first candidates for the compose-lint profile catalog.

Two derivation signals are used, and the netdata case shows why **both** are
needed:

- **Runtime observation** (`csd --observe …`) — what the container exercises
  *while running*. Fast, evidence-backed, but blind to **startup** privileges a
  container uses once during init.
- **Bisection** (drop a cap → restart → verify) — covers the **full container
  lifetime**, so it catches startup caps observation cannot. `scripts/bisect_caps.sh`
  automates the general case; the netdata run below used a service-specific driver.

All runs used `ig v0.51.0` (the pinned version) on Linux 6.18.

---

## netdata/netdata:v2.10.3 — capabilities

`sha256:bcc822ec685dd7ee488e9f99b957f479b66301be04f13f346df692ad7de94151`

netdata is commonly granted a broad `cap_add` set (often 7+ caps plus
`security_opt: apparmor:unconfined`). To profile it representatively it must run
the way it is actually deployed — as a **host monitor**: `--pid host`, host
`/proc`,`/sys`,`/var/run/docker.sock` read-only mounts, `--network host`, and
**the granted caps present** (a denied cap check is filtered out, so an ungranted
cap reads as "unused"). A vanilla `docker run netdata/netdata` observes only
`DAC_OVERRIDE`; the representative run observes the real set.

### Runtime observation — `csd --observe capadd --cap-add <granted 7>`

| Cap | Runtime events | Verdict |
|---|---|---|
| `SYS_PTRACE` | 41,780 | used |
| `DAC_OVERRIDE` | 7,507 | used |
| `SYS_ADMIN` | 2 | used |
| `CHOWN` | 0 | flagged removable |
| `FOWNER` | 0 | flagged removable |
| `SETUID` | 0 | flagged removable |
| `SETGID` | 0 | flagged removable |

`trace_health.drop_rate` was **16%** on this run (netdata under `pid:host` is
extremely high-volume), so confidence graded **low** — a cap exercised only a
handful of times could itself be dropped and read as unused. The runtime verdict
alone is not safe to act on.

### Bisection — drop each candidate, restart, verify (health **and** privilege drop)

The definitive signal is the netdata daemon's UID: it drops root → `netdata`
user (uid 201) at startup **iff** it can.

| Dropped cap | Health | Daemon UID | Verdict |
|---|---|---|---|
| baseline (all 7) | healthy | 201 | — |
| `CHOWN` | healthy | 201 | ✅ removable |
| `FOWNER` | healthy | 201 | ✅ removable |
| `SETUID` | healthy | **0 (root!)** | ❌ **required** — privilege drop fails |
| `SETGID` | healthy | **0 (root!)** | ❌ **required** — privilege drop fails |

**Verified minimum: `[SYS_PTRACE, SYS_ADMIN, DAC_OVERRIDE, SETUID, SETGID]`** (7 → 5).

The lesson: `SETUID`/`SETGID` fire only at startup for the root→user privilege
drop, which runtime observation cannot see. Dropping them on the observation
verdict leaves netdata **"healthy" while silently running as root** — a
health-check gate would not catch it. Only bisection (full lifetime, asserting
the UID) does. `CHOWN`/`FOWNER` are genuinely unused because the image ships its
data dirs already `netdata`-owned.

Applied and verified live: the 5-cap config deploys healthy, container running,
netdata daemon still uid 201, `apps.plugin` (needs `SYS_PTRACE`) collecting.
`SYS_ADMIN` is exercised at runtime and retained (which specific collector needs
it was not isolated). `apparmor: unconfined` is not observable by csd (no denial
gadget at the pin — the known `security_opt` gap).

---

## postgres:16 — read-only filesystem

`sha256:fe03a7605299a34ddf5e4f285dff78c3d7190a576b3c6b46f2fcff69f4bffd54`

`csd --observe fs` over a ≥300s window driving a representative SQL workload
(connect / CREATE / INSERT / SELECT / DROP / reload):

- 147+ write events, 0 dropped. Every observed write correlated to the postgres
  **data volume** (`/var/lib/postgresql/data`), so nothing needs a rootfs write.
- Observation recommendation: **`read_only: true`, `tmpfs: []`**.
- Confidence **moderate**, digest-pinned, `duration_seconds: 310`.

**Correction (drop-test):** the observation-only `tmpfs: []` was **wrong**.
postgres creates its socket dir `/run/postgresql` **once at startup**, which is
attach-window-blind to runtime observation — under `read_only:true` with no
tmpfs it fails: *"could not create lock file /var/run/postgresql/…: Read-only
file system"*. The catalog profile is drop-test-derived: **`read_only: true`,
`tmpfs: [/run/postgresql]`**. This is the canonical case for why drop-test, not
observation, is authoritative for filesystem/startup requirements. The
`--format compose-lint-profile` document clears `scripts/validate_profiles.py`.

---

## gethomepage/homepage:v1.13.2 — read-only filesystem (already minimal)

`sha256:a0b71c8e757298d02560186bab9fbe3fc2d375c523a62cc1019177b37e48aa28`

`csd --observe fs` while driving the dashboard + API (`/`, `/api/config/layout`,
`/api/widgets`) observed **zero rootfs writes** (config + logs go to the mounted
config volume; the Next.js runtime cache belongs on tmpfs). csd's recommendation
— `read_only: true` with `/app/.next/cache` on tmpfs — **matches a
correctly-hardened deployment**. Here csd's role is *verification*, not change:
it confirms the minimal posture rather than proposing a reduction.

Note: a clean read-only workload paradoxically grades **low** confidence in the
fs *observation* rubric — zero writes is zero *signal*, indistinguishable from
"missed the writes" by count alone. csd is honest about this rather than
over-claiming.

**Follow-up (drop-test):** the catalog profile is now drop-test-derived at **high**
confidence — `read_only: true`, `tmpfs: [/app/.next/cache]`. The subtlety
observation glossed: a bare dashboard `GET` serves read-only, but Next.js **image
optimization** (`/_next/image`, used for icons) `mkdir`s `/app/.next/cache` and
errors when it isn't writable. The drop-test correctness check exercises image
optimization, so the requirement is confirmed rather than assumed; `/tmp` was
drop-tested and is not required, and `/app/config` is a persistent volume.

---

## Methodology notes (carry into the derivation automation)

1. **Reproduce the service's real runtime config.** Caps/mounts/`pid`/`network`
   mode change what a container exercises. Read them from the service's own
   compose; do not profile a vanilla `docker run`.
2. **Observe *and* bisect for `cap_add`.** Observation finds the runtime set;
   bisection confirms the minimum and catches startup caps. Neither alone is
   sufficient.
3. **"Healthy" ≠ "correct."** A container can pass its health-check while running
   with the wrong privilege (root). Assert the intended posture (e.g. the daemon
   UID), not just liveness.
4. **Digest-pin.** Every result above is tied to the exact `image@sha256:…` it
   was derived against; a digest bump is the trigger to re-derive.
