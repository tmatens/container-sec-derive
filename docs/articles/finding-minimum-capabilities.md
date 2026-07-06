# Finding the minimum capabilities a container actually needs

Most `cap_add` lines in the wild were copied from a README and never revisited.
Someone hit a permission error, found a Stack Overflow answer that said "add
`SYS_ADMIN`," it worked, and it shipped. Multiply that across a compose file and
you have a stack running with far more privilege than any of its services use —
each extra capability a little more of the host you've handed to a process that,
one CVE later, an attacker controls.

This article is about how to stop guessing. It explains what Linux capabilities
are, *where they actually show up* in real containers, and how to find the true
minimum a container needs — including the subtle case where a container "works"
but is quietly running with a privilege it shouldn't have. The method is
tool-agnostic: you can do all of it by hand with plain Docker. A tool like
[`container-sec-derive`](https://github.com/tmatens/container-sec-derive) (csd)
automates the slow parts, and the worked examples below come from real csd runs,
but you don't need it to follow along or to harden your own stack.

## What a capability is

Historically a Linux process was either root (uid 0, can do anything) or not. That
is a terrible security model: a web server that needs to bind port 80 — a
one-second, one-syscall privilege — had to run as full root to get it.

**Capabilities** break root's power into ~40 discrete privileges that can be
granted independently. Instead of "root or not," a process holds a *set*: bind low
ports (`CAP_NET_BIND_SERVICE`), override file permission checks
(`CAP_DAC_OVERRIDE`), change file ownership (`CAP_CHOWN`), trace other processes
(`CAP_SYS_PTRACE`), and so on. Drop the ones it doesn't need and a compromise of
that process buys the attacker much less.

In Docker/Compose the model you want is:

```yaml
cap_drop: [ALL]          # start from zero
cap_add: [NET_BIND_SERVICE]   # add back only what this service uses
```

`cap_drop: [ALL]` then a short `cap_add` is *deny-by-default*: the container starts
with no capabilities and you enumerate exactly what it needs. Contrast this with
`privileged: true`, which is the opposite — a blunt instrument that grants **all**
capabilities *plus* all device access, an unconfined AppArmor/seccomp profile, and
more. `privileged: true` almost always means "I didn't want to figure out what was
actually required." The whole point of this exercise is to replace it with the
handful of specific grants it was standing in for.

## Where capabilities actually show up

You don't need all 40. In real self-hosted workloads the same handful recur,
each tied to a concrete thing a container does and a syscall it makes:

| Capability | What it lets the process do | Where you see it |
|---|---|---|
| `NET_BIND_SERVICE` | bind a port below 1024 | a server listening on `:80`/`:443` directly (`bind()`) |
| `SETUID` / `SETGID` | change process uid/gid | dropping root → an app user at startup (`setuid()`/`setgid()`) |
| `CHOWN` / `FOWNER` | change file ownership / bypass ownership checks | an entrypoint `chown`-ing a data dir before use (`chown()`) |
| `DAC_OVERRIDE` | bypass file read/write/execute permission checks | reading a file the process's uid doesn't own |
| `SYS_PTRACE` | inspect another process's memory / `/proc` | a monitoring agent reading per-process metrics (`process_vm_readv()`, `ptrace()`) |
| `NET_RAW` | use raw/packet sockets | a container that runs `ping` (ICMP) |
| `SYS_ADMIN` | a giant grab-bag (mounts, namespaces, more) | the "it needed something and this fixed it" cap — almost always over-broad |

`SYS_ADMIN` deserves the callout: it is so broad it is often described as "the new
root." If a README tells you to add it, that is exactly the case worth
investigating, because a finer capability (or none) is usually what's really
needed.

## The two failure modes

There are two ways to get capabilities wrong, and they pull in opposite
directions.

**Over-granting** is the obvious one: cargo-culted caps, a stray `SYS_ADMIN`, or
`privileged: true` where three specific caps would do. This is what most hardening
advice targets, and it's real — but it's the *easy* failure, because the container
works and you can tighten it at your leisure.

**The subtle one is a container that "works" but shouldn't have the privilege.**
This is the failure that bites you, because nothing looks wrong. The container is
up, its health-check is green, and it is silently running with more power than it
should — often because a privilege it needed *at startup* was removed, and the
program fell back to a less-safe path instead of failing loudly. The netdata case
below is exactly this, and it's the reason the naive approach — "drop caps until
something breaks" — is not enough on its own.

## How to find the real minimum: two methods, and why you need both

There are two complementary ways to learn what a container needs. Each has a blind
spot the other covers, so the honest answer uses both.

**1. Runtime observation** — watch what the container actually exercises *while
running*. Drive the service through its real paths (log in, serve a request, run a
query) and record which capabilities its syscalls invoke. This is fast and
evidence-backed: you see `SYS_PTRACE` fire 41,780 times and know it's used. Its
blind spot is **startup**: a capability a container uses *once* during
initialization — before you attached, or in a helper that has already exited — is
invisible. You can't observe what already happened.

**2. Bisection** — drop one capability, restart the container, and verify it still
works correctly; repeat for each. This covers the **whole container lifetime**,
startup included, because every trial includes a fresh boot. Its cost is that it's
slower (one restart per candidate) and it is only as good as your definition of
"still works correctly" — which turns out to be the crux.

```
                 startup            steady-state runtime
                 |------|-----------------------------------|
observation:            [==== sees only this window ========]   ← misses startup
bisection:       [==== restart covers the whole lifetime ===]   ← sees startup too
```

The thing that makes bisection trustworthy is the **correctness check**. "The
container is still running" is not "the container is correct." If you drop a
capability and merely check that the container is up — or that its `/health`
endpoint returns 200 — you will accept a container that boots but is broken, or one
that's running with the wrong privilege. A health/liveness endpoint is *designed*
to stay green as long as the process is alive; it tells you nothing about whether
the service is doing its job. So a correctness check must assert the service's real
function: a request served with the *correct* status, a non-root uid, non-zero
collected data. Hold onto that — the headline example turns on it.

## Worked example: netdata, 7 → 5 capabilities

[netdata](https://github.com/netdata/netdata) is a monitoring agent, and it's
commonly deployed with a broad grant — seven capabilities plus
`apparmor:unconfined` — because it's a host monitor and "monitoring needs
privilege." Let's find what it actually needs. (These are real numbers from
`netdata:v2.10.3`, run the way it's actually deployed: `--pid host`, host
`/proc` + `/sys` mounts, `--network host`, all seven caps present.)

**Step 1 — runtime observation.** Watch which caps fire while netdata runs and
collects:

| Capability | Runtime events observed | Verdict |
|---|---|---|
| `SYS_PTRACE` | 41,780 | used |
| `DAC_OVERRIDE` | 7,507 | used |
| `SYS_ADMIN` | 2 | used |
| `CHOWN` | 0 | looks removable |
| `FOWNER` | 0 | looks removable |
| `SETUID` | 0 | looks removable |
| `SETGID` | 0 | looks removable |

Tempting conclusion: drop the four zero-event caps, keep three, done. **This is the
trap.** Two of those four are startup caps — they fired once, before observation
attached, and observation is blind to them.

**Step 2 — bisection.** Drop each candidate, restart, and check the thing that
actually matters. For netdata the definitive signal is the daemon's uid: netdata is
*supposed* to drop from root to its own `netdata` user (uid 201) at startup — but
only if it *can*.

| Dropped cap | Health-check | netdata daemon uid | Verdict |
|---|---|---|---|
| baseline (all 7) | healthy | 201 | — |
| `CHOWN` | healthy | 201 | ✅ genuinely removable |
| `FOWNER` | healthy | 201 | ✅ genuinely removable |
| `SETUID` | healthy | **0 (root!)** | ❌ **required** |
| `SETGID` | healthy | **0 (root!)** | ❌ **required** |

Look at the `SETUID`/`SETGID` rows. The health-check is **still green** — netdata is
up and answering. But the daemon is running as **root**, because without
`SETUID`/`SETGID` its startup attempt to drop privileges *failed silently* and it
carried on as root. Observation said "unused" (the drop happens once at startup,
invisibly); a health-check says "fine" (the process is alive); and both are wrong
in the most dangerous way — they'd have you ship a monitoring agent running as root
on your host and never know.

`CHOWN` and `FOWNER`, by contrast, are genuinely removable: the image ships its data
directories already owned by the `netdata` user, so it never needs to chown
anything.

**Verified minimum: `[SYS_PTRACE, SYS_ADMIN, DAC_OVERRIDE, SETUID, SETGID]` — 7 → 5.**
Applied and confirmed live: the container comes up healthy, the daemon runs as
uid 201, and `apps.plugin` (which needs `SYS_PTRACE` for per-process metrics) keeps
collecting. Two caps removed, two dangerous mistakes avoided.

Three lessons in one example:

- **"Healthy" ≠ "correct."** A green health-check told you nothing about the fact
  that the container was running as root.
- **Runtime observation is blind to startup.** The two required caps showed *zero*
  events, because their one use happened during init.
- **Your correctness check is the whole game.** Bisection only caught this because
  the check asserted the daemon's **uid**, not just liveness. A weaker check would
  have "proven" `SETUID`/`SETGID` removable and shipped the root container. (There's
  a mirror image of this: too *narrow* a check under-derives. Against a netdata check
  that confirmed "up + non-root" but never exercised per-process monitoring,
  `SYS_PTRACE` and `SYS_ADMIN` also looked removable — because the workload never
  made netdata use them. The minimum is only ever valid for what you actually
  exercise.)

## Capabilities aren't the only privilege axis: postgres

Hardening is more than caps. `postgres:16`, watched over a five-minute window
driving a real SQL workload (connect / CREATE / INSERT / SELECT / DROP / reload),
made **147+ writes, every one to its data volume** (`/var/lib/postgresql/data`) —
nothing written to the container's root filesystem. So it can run read-only:

```yaml
read_only: true
```

But here's the same startup blind spot again, in a different dimension.
Observation alone recommended `read_only: true` with **no** tmpfs — and that's
**wrong**. postgres creates its socket directory `/run/postgresql` **once at
startup**; under `read_only: true` with no writable tmpfs there, it fails hard:
*"could not create lock file /var/run/postgresql/…: Read-only file system."*
Observation missed it for the same reason it missed netdata's `SETUID` — it happens
during init. The bisection-derived answer, which restarts and therefore sees
startup, is:

```yaml
read_only: true
tmpfs: [/run/postgresql]
```

Same moral as netdata: the authoritative signal for anything that happens at
startup is drop-and-restart, not runtime observation.

## What "done right" looks like: homepage

Not every service needs fixing. [homepage](https://github.com/gethomepage/homepage)
(`v1.13.2`), driven through its dashboard and API, wrote **zero** bytes to its root
filesystem — config and logs go to a mounted volume. Its minimal posture is
`cap_drop: [ALL]`, `read_only: true` with `/app/.next/cache` on tmpfs,
`no-new-privileges`, non-root. Here the exercise is *verification*, not reduction:
you confirm the container is already minimal rather than proposing a change. That's
a perfectly good outcome — knowing a service is tight, with evidence, is worth as
much as tightening a loose one.

homepage also has its own small startup subtlety, and it's a nice one to end on. A
bare dashboard `GET` serves fine read-only — but Next.js **image optimization**
(`/_next/image`, used to render the dashboard's icons) does a `mkdir` of
`/app/.next/cache` and errors if it can't write there. A correctness check that
only loaded the bare page would miss it; one that actually requests an optimized
image catches it. Once more: what you verify is bounded by what you exercise.

## Doing it yourself

None of this needs special tooling. The bisection method is plain Docker:

1. Start from the service's current config and a **correctness check you trust** —
   a command that proves the service is doing its real job (serves the right
   response, runs as the expected uid, returns non-empty data). *Not* a `/health`
   endpoint.
2. For each capability the service is granted, restart the container **without**
   that one and run your correctness check.
   - Check **passes** → the cap wasn't needed; leave it out.
   - Check **fails** → it's required; add it back.
3. The caps that survive as required are your `cap_add`. Everything else goes, under
   `cap_drop: [ALL]`.

The two things that make or break this: restart for **every** trial (so startup is
covered), and make the correctness check assert **function and privilege**, not
liveness (so you catch the "healthy but wrong" cases). Do the same drop-and-restart
loop for `read_only: true` + `tmpfs:` paths and you've covered the filesystem axis
too.

Runtime observation — the eBPF path that produced the event counts above — is the
faster, automated complement: it tells you the *runtime* set in one pass so you have
fewer candidates to bisect, and it's what a tool like csd is for. But it is a
*complement*: as netdata and postgres both show, observation cannot see startup, so
bisection is the authority for anything that happens once at boot. Use observation to
go fast; use bisection to be sure.

## The rules worth keeping

- **`cap_drop: [ALL]` first, then add back the minimum.** Deny by default.
- **Replace `privileged: true` with the specific caps + devices it was covering.**
  It's almost never actually all of them.
- **Observe *and* bisect.** Observation finds the runtime set fast; bisection
  catches startup caps and confirms the minimum. Neither alone is sufficient.
- **"Healthy" ≠ "correct."** Assert the service's real function and its intended
  privilege (e.g. the process uid), never just a liveness endpoint.
- **Pin the image digest.** A minimum is only valid for the exact image it was
  derived against; a digest bump is your cue to re-derive.

Copying a `cap_add` from a README is a guess. Restarting the container without a
capability and watching whether it still does its job — correctly — is a
measurement. The gap between the two is the attack surface you didn't know you were
shipping.

---

*The netdata (7→5), postgres, and homepage figures here are from real
digest-pinned runs recorded in [docs/field-results.md](../field-results.md). The
runtime-observation vs. bisection methodology, and the correctness-check rule
("exercise function, not liveness"), are covered in
[docs/re-derive-at-deploy.md](../re-derive-at-deploy.md); `scripts/bisect_caps.sh`
automates the general bisection case.*
