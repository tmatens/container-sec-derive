# Re-derive at deploy

The robust way to consume a security profile is to **derive it against the actual
deployment**, not to loose-match a generic catalog entry by image name.

## Why loose-matching is fragile

A derived minimum is a function of **(image digest × exact invocation × workload
coverage)**. A static consumer (e.g. compose-lint enrichment) matches a service
to a catalog profile by image *name* and throws all three away — it can't see the
invocation, so it can hand back a minimum derived under conditions the service
doesn't share. The sharpest case: a service run with `user:` set skips the
root→user privilege drop and needs **none** of the startup caps a
default-invocation profile lists.

## The bridge: `scripts/compose_derive.sh`

Re-derivation against the real invocation removes the *matching* guesswork. The
bridge reads a service out of a compose file, extracts its run config — image,
`user`, `command`, `network`/`pid` mode, `security_opt`, mounts, `environment`,
and the granted cap set (its `cap_add`, or the Docker default set) — generates a
drop-test spec, and runs it:

```sh
CORRECTNESS=testdata/drop-test/correctness/<svc>.sh \
  scripts/compose_derive.sh docker-compose.yml <service>
```

It emits the same evidence JSON as `scripts/drop_test.sh`, including the
`run_config` block, so the result records exactly the invocation it was derived
under.

## Proof: same image, different invocation, different minimum

`postgres:16`, drop-tested through the bridge under two compose configs:

| compose | derived cap minimum |
|---|---|
| default (root, entrypoint drops to postgres via `gosu`) | `[DAC_OVERRIDE, SETGID, SETUID]` |
| `user: "999"` + a pre-owned data volume | `[]` — needs nothing |

Same image; the invocation decides the answer. A catalog matched by image name
would apply one of these to both services — over-granting three capabilities on
the second, or (in the read-only case) shipping a set that breaks the first.
Re-deriving against each service's own config is correct for both.

## Proof: a custom build changes the minimum (caddy)

The bridge builds a service's `build:` image and derives against *that* — because
the built image can differ from any base tag in a security-relevant way. The
homelab caddy is the case in point. Its Dockerfile is `xcaddy build …` in a
builder stage then `COPY --from=builder /usr/bin/caddy`. The base `caddy:2` binary
carries the file capability `cap_net_bind_service=ep` — with it, dropping the cap
from the container's bounding set makes even `execve` fail (`exec /usr/bin/caddy:
operation not permitted`), so a drop-test of the base image reports
`NET_BIND_SERVICE` **required**. But **Docker's `COPY` strips file capabilities**,
so the *deployed* binary has none; combined with the container's default
`ip_unprivileged_port_start=0` (any process may bind a low port), caddy binds
:80/:443 without the cap. Deriving against the actual build yields minimum `[]` and
a verdict of `over_permissioned — drop [NET_BIND_SERVICE]`. But that verdict is
*bounded* by the runtime, not settled by it: caddy runs as **root**, so the granted
cap still binds :80 when the container's `port_start` is tightened to 1024, and
dropping it fails there (`bind: permission denied`) — both verified. The cap reads
removable only because of the loose default sysctl; it is a defense-in-depth grant,
not a clear over-permission (see "Custom images: a principle").

A service whose config references secrets it doesn't have on the derive host — a
`${CF_API_TOKEN}` in caddy's env — has those `${VAR}` values replaced by a
synthetic placeholder so the config still loads (Caddy refuses to start on a
literal `${…}`); no real secret ever touches the derive host, and capability needs
come from structure, not a token's value.

## The deploy check: compare the minimum to what the service declares

Deriving the minimum is only half of a gate — the actionable output is the diff
against what the service *already declares*. After the drop-test, the bridge
compares the derived minimum to the service's `cap_add`/`cap_drop` and emits a
`deploy_check` block plus a one-line stderr verdict:

```
$ compose_derive.sh docker-compose.yml db     # db declares cap_add:[SYS_ADMIN, DAC_OVERRIDE, SETGID, SETUID]
compose_derive: over_permissioned — over-permissioned: drop ['SYS_ADMIN'] (declared, not needed)
```
```json
"deploy_check": {
  "recommended": { "cap_drop": ["ALL"], "cap_add": ["DAC_OVERRIDE","SETGID","SETUID"] },
  "declared":    { "cap_drop": ["ALL"], "cap_add": ["DAC_OVERRIDE","SETGID","SETUID","SYS_ADMIN"] },
  "verdict": "over_permissioned", "drop": ["SYS_ADMIN"], "add": []
}
```

Verdicts: **`matches`** (declared == minimum), **`over_permissioned`** (grants
caps it doesn't need → `drop`), **`under_permissioned`** (missing caps the
workload needs → `add`; this one would break at runtime), and **`not_minimized`**
(no `cap_drop: ALL` — recommend dropping all and adding the minimum). The
candidate set is the declared `cap_add` **unioned** with the Docker default set,
so both over-grants and missing caps are detectable.

The **exit code is the gate signal** — `0` matches, `10` not-minimized, `11`
over-permissioned, `12` under-permissioned — so a job can `fail >= 12` and warn
on the rest, or pick its own threshold.

## The part re-derivation does *not* solve: the correctness check

Deriving against the real config removes the matching guesswork, but **not** the
need for a per-service correctness bar. "The container is still running" is not
"the container is correct" — netdata drops `SETUID`/`SETGID`, stays up, and runs
as **root**. The built-in `correctness/compose_generic.sh` (container stays
running) is a floor, and its weakness is deliberate and documented; a real
derivation should assert the intended posture — a request served, a non-root uid,
a passing workload — which is per-service knowledge, supplied via `CORRECTNESS`.

**A correctness check must exercise real function — never a health/liveness
endpoint.** `/health`, `/healthz`, `/api/healthcheck`, and liveness probes are
*designed* to stay green as long as the process is up; they say nothing about
whether the service does its job. Two ways this bites, both seen here:

- **netdata:** drop `SETUID`/`SETGID` and it runs "healthy" *as root*; drop
  `SYS_PTRACE` and `apps.plugin` reports every per-process metric as **0** (not
  null) — still "healthy". A liveness probe passes a functionally-broken,
  wrongly-privileged container.
- **homepage:** `/api/healthcheck` returns 200 ("up") while the dashboard `/`
  500s because its config isn't writable by the run uid.

A green health endpoint over a broken service does double damage: it accepts the
broken container *and* it hides an inadequate correctness check — you can't tell
whether a cap is genuinely removable or whether your check simply can't see the
breakage (the `fixed`-list trap `scripts/drop_test.sh` documents). So a correctness
check asserts the service's real function: a served request with the *correct*
status, a non-root uid, non-zero collected data, a passing workload. A
readiness/health endpoint may be used as a **wait gate** (poll until the service is
up before probing), but never as the correctness *assertion* — the pattern the
`alloy`, `loki`, `grafana`, and `redis` checks follow (ready-gate, then a real
read/write). Audited 2026-07-06: every `testdata/drop-test/correctness/*.sh`
follows this rule.

**And even a decent correctness check can under-derive.** Run against a real homelab
netdata (`cap_drop:[ALL]` + `cap_add:[SYS_PTRACE, SYS_ADMIN, DAC_OVERRIDE,
SETUID, SETGID]`, `pid:host`, host mounts) with a correctness check that asserts "ready +
non-root uid + apps.plugin up", the deploy check returned:

```
compose_derive: over_permissioned — drop ['SYS_ADMIN', 'SYS_PTRACE'] (declared, not needed)
```

That verdict is **wrong**, and instructively so. `SYS_PTRACE` is what lets
`apps.plugin` read *per-process* metrics (tens of thousands of events in a live
run); `SYS_ADMIN` serves a collector. The correctness check confirmed netdata was *up and
non-root* without exercising per-process monitoring, so those two caps looked
removable. The minimum is only ever valid for what the correctness check exercises —
**workload coverage bounds the answer**, and a readiness check is not full
coverage. Re-deriving against the real config removes the *matching* guesswork
but inherits the correctness check's blind spots; a deploy check is only as trustworthy
as the correctness bar behind it.

**The tempting escape hatch — and why it's closed.** When a cap looks removable
but you *believe* it's needed, the tempting move is to mark it `fixed` in the
drop-test spec: always granted, always emitted in the minimum, never tested. The
tool **rejects a non-empty `fixed`** (exit 5), because it hides the exact failure
you're looking at: a cap you can't prove needed is the correctness check telling
you it can't see the breakage — `fixed` just silences that signal, and would have
shipped netdata's genuinely-removable `SYS_ADMIN` forever. There are two honest
responses instead: **(1) strengthen the correctness check** so the cap becomes a
testable candidate (for netdata's `SYS_PTRACE`, assert a per-process metric is
*non-zero* — a denied `apps.plugin` reports 0, not null); **(2)** if it genuinely
can't be exercised in the window, record it as a **criteria-doc caveat + low
confidence**, not an untested entry laundered into a "derived" minimum. (This is
the caps/paths `fixed` list — distinct from the invocation and sibling-dimension
context in `run.*`, which *is* legitimately held constant.)

## The derive environment must match the target

A capability is "required" only if removing it *breaks something* — so if the
**derivation host** lets the operation through anyway, the drop-test calls the cap
removable even when a stricter target would need it. Two knobs:

- **Host kernel posture** — e.g. `kernel.unprivileged_bpf_disabled`, kernel
  lockdown. A host that permits unprivileged eBPF lets a container load eBPF
  *without* `SYS_ADMIN`/`CAP_BPF`; a hardened host does not.
- **The container's applied MAC/seccomp** — running the test container
  `apparmor:unconfined` (or with seccomp off) removes a constraint the target
  enforces.

`netdata`'s `SYS_ADMIN` is the worked case: `ebpf.plugin` (enabled in its config)
loaded *with or without* the cap on a permissive derive host — root, ambient BPF,
`apparmor:unconfined` — so the drop-test couldn't prove it required, and reported
it as an over-grant. A locked-down prod host would need it. **To derive
`SYS_ADMIN` / BPF- / MAC-adjacent capabilities trustworthily, the derive host must
match the target's security baseline** (kernel settings, default seccomp/apparmor).
This is a third axis of *context bounds validity*, alongside the invocation and
workload coverage. On a mismatched host, treat such caps as conservatively kept,
not removable — the drop-test can prove a cap *needed* (removing it broke
something) but cannot prove one *unneeded* if the environment never enforced it.

## Reproducing the invocation faithfully: bind-mount ownership

Matching the host posture isn't enough; the *invocation's own preconditions* have
to hold too. The sharp case is a bind mount under a numeric `user:`. A service
that runs as `user: "1000:1000"` and binds `./config` does so because, on the
deploy target, `./config` is **owned by uid 1000** — so the process reads and
writes its own files and needs no capability for them. A fresh `git clone` on the
derive host owns that directory as the *cloning* user instead. Run the container
as 1000 against it and every write is EACCES: homepage, for one, can't create
`config/logs`, so its dashboard 500s (while `/api/healthcheck` still reports "up" —
the same "healthy but wrong" trap netdata sprang). The baseline never becomes
correct and nothing can be derived.

The fix is to **reproduce the ownership**, not to loosen permissions.
`drop_test.sh`, when a spec pins a numeric run uid, stages a private copy of each
bind-mounted directory and `chown`s it to that uid (using the service image itself
as a root-in-container helper, so no host root is needed). Matching ownership is
what removes the capability need — exactly as on the target. Making the mount
world-writable instead would leave it owned by the *wrong* uid, and a process
touching files it doesn't own can trip `FOWNER`/`CHOWN`: the derived minimum would
then be wrong in the other direction. Ownership is the load-bearing property, so
ownership is what gets reproduced.

## Custom images: a principle

The caddy case (above) yields two rules for a locally-built (`build:`) image:

1. **A custom image never becomes a published catalog profile.** A catalog profile
   is digest-pinned and meant to be pulled and reused by anyone running that image;
   a profile for a build only you can produce is neither pullable nor reproducible
   by others, so it can't be verified or shared. Deriving against a custom image
   belongs to **deploy-check** — a verdict on *your own* deployment —
   never to the catalog, which targets public, pullable images.

2. **"The capability reads removable" is not the same as "safe to drop" — ask what
   is actually providing the function.** caddy is the cautionary case. The
   drop-test derives `NET_BIND_SERVICE` as removable, and for the *current* runtime
   that's true — but only because the container's default
   `ip_unprivileged_port_start=0` lets **every** process bind low ports. caddy runs
   as **root**, so the granted `cap_add: [NET_BIND_SERVICE]` is its fallback: with
   the grant it still binds :80 when `port_start` is tightened to 1024; without it,
   that same host returns `bind: permission denied` (both verified). So the grant
   isn't dead weight — it's cheap insurance against a hardening change, and the
   *only* thing binding the port today is a blanket sysctl. Dropping it trades a
   tiny attack-surface reduction for fragility. (The stripped file capability is a
   **red herring** here: a root process gets the granted cap regardless, and a
   file-cap binary would still need the cap in its *bounding set* to `exec` —
   restoring it via `setcap` in the final stage buys nothing. It would only matter
   for a *non-root* caddy, where a file cap can grant the bind without a broad
   `cap_add`.)

The general rule behind (2): **a capability reading "removable" can mean it is
genuinely unused, or that a broader control is quietly covering for it** — drop it
then and you're left with only the broad control. The deploy-check reports the
mechanical fact (the grant is currently redundant); acting on it needs to know
*what* makes it redundant and whether that's the posture you want to depend on.

## Where it belongs

This is a **deploy/promote-time** concern, not an authoring-time one: that's where
the exact image + config are in hand, and where the result can gate. It
complements — does not replace — the static authoring hint, which stays advisory
(a pointer that admits it can't see your runtime).

**It does not belong *inline* in the deploy hot path.** The drop-test takes
minutes per service and spins up throwaway containers under varied cap sets — far
too heavy to run inside `deploy.sh` before a `docker compose up`. The right home
is a **scheduled / on-demand job on the self-hosted BPF runner** (the same place
the catalog re-derivation loop runs): it reads the services' committed compose
files, runs the deploy check against each, and reports verdicts (or opens a PR /
fails on `under_permissioned`) — off the deploy critical path, on image-digest
bumps and on a schedule. `deploy.sh` stays fast; the security check runs beside
it, not within it.

## Invoking it

Per service, as a first-class subcommand (#355):

```sh
csd deploy-check --compose docker-compose.yml --service immich-db
```

Evidence JSON (with the `deploy_check` block) on stdout, the one-line verdict +
progress on stderr. Exit codes separate **couldn't derive** from a **security
verdict**: `3` cannot-run (build/drop-test failed), `12` under_permissioned (a
needed cap is undeclared — the hardened deploy would break; always non-zero),
and `10`/`11` not_minimized/over_permissioned (advisory by default, non-zero
under `--enforce`). `--correctness <path>` supplies a per-service app-tier
oracle; `--out <path>` also writes the evidence JSON; `--script-dir` points at
csd's `scripts/` (the subcommand runs from a repo checkout on the BPF derive
host, as `deploy-check.yml` does via `actions/checkout`). The subcommand is a
thin Go wrapper over `scripts/compose_derive.sh` — the live drop-test trials and
the hermetically-tested compose parse/verdict stay in shell/python. The fleet
driver (`scripts/deploy_check.sh`, driven by `deploy-check.yml`) is the
multi-service equivalent, iterating `deploy-check/manifest.yaml`.

## Status

**Capabilities dimension**, first-class as `csd deploy-check` (#355). Handles a
pulled `image:` or a `build:` image (built locally, derived against the actual
artifact), with unresolved `${VAR}` env replaced by a placeholder. Follow-ups:
the filesystem dimension (derive `read_only`/`tmpfs` from the service), a growing
library of per-service correctness checks, and the deploy-pipeline integration
itself.
