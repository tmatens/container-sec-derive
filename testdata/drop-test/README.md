# drop-test producer

`scripts/drop_test.sh` derives a **required minimum** by *removing each candidate
and verifying the container breaks without it*. It is csd's **experiment** layer,
complementary to the **observation** layer (the ig gadgets) — and, unlike a
gadget, it is not eBPF: it drives the container runtime and runs an
application-level correctness check.

- **Observation** (`caps`/`fs`/… → `bpf-observation`) answers *"what did it
  exercise?"* — blind to startup-only requirements (a root→user privilege drop's
  `SETUID`/`SETGID`, a socket dir's tmpfs).
- **drop-test** (→ `drop-test`) answers *"what does it require?"* — the only
  method that catches those. Method: *leave-one-out* elimination.

The result feeds a compose-lint profile's `observer: drop-test` /
`validated_via: [drop-test, …]` dimension (compose-lint ADR-017 §8), and its
`checks` are the `derivation.drop_test` evidence.

The evidence also carries a **`run_config`** block — the invocation the minimum
was derived under (`user`, `command`, `entrypoint`, `network`, `pid`, `devices`,
`security_opt`, `mounts`, and `env` as **keys only**, no values, so a secret
never lands in committed evidence). It
is a byproduct of the run, not hand-authored: a derived minimum is only valid for
*this* invocation, so a consumer can diff a target service against it and warn
when a load-bearing axis diverges. postgres is the sharp case — under the default
(root-then-`gosu`-drop) invocation it needs startup caps like `SETUID`/`SETGID`;
run with `user:` set it skips the drop and needs neither.

## Usage

```sh
PY=python3 scripts/drop_test.sh testdata/drop-test/<spec>.yaml   # -> evidence JSON
```

A **spec** names the image/tag, the dimension (`capabilities` | `filesystem`),
the representative run config, the `fixed` set (always granted, not tested), the
`candidates` to drop-test, and a `correctness` check script. The **correctness
check** is the per-image test of whether the service actually works — it returns
0 iff the container is *correct* (not merely alive), reading the container name
from `$DROP_TEST_CONTAINER`.

## Specs

- **`postgres-fs.yaml`** — filesystem. **Validated end-to-end**: dropping
  `/run/postgresql` makes postgres fail to start (socket dir), so it is required.
- **`netdata-caps.yaml`** — capabilities. **Validated end-to-end.** The correctness check
  asserts the daemon still drops to a non-root uid (the "healthy-while-root"
  trap): dropping `SETUID`/`SETGID` leaves it running as root (required),
  `CHOWN`/`FOWNER` do not (removable). Verified minimum
  `[DAC_OVERRIDE, SETGID, SETUID, SYS_ADMIN, SYS_PTRACE]`. Run as a host monitor
  (`pid:host`, host `/proc`,`/sys`,`docker.sock` ro-mounts, host network, the
  granted set present).
- **`caddy-caps.yaml`** — capabilities. **Validated end-to-end.** Baseline
  `cap_drop:ALL` + the Docker default set; dropping each and re-verifying the
  file server serves on `:80` leaves only `[NET_BIND_SERVICE]` (matches the
  bisected `testdata/caddy/ground_truth.json`).
- **`caddy-fs.yaml`** — filesystem. **Validated end-to-end.** caddy serves under
  `--read-only`; `/data` (certs) and `/config` (autosave) drop-test as
  not-required-as-tmpfs → `read_only:true, tmpfs:[]` (those paths belong on
  persistent volumes, not tmpfs — the honest contrast to postgres's ephemeral
  socket dir). Shared correctness check `correctness/caddy.sh` (serves a `GET` on `:80`,
  via `docker exec` so no host ports are published).
- **`postgres-caps.yaml`** — capabilities. **Validated end-to-end.** Baseline
  `cap_drop:ALL` + the Docker default set on a fresh data dir (so initdb + the
  root→postgres `gosu` drop run); dropping each and re-verifying the workload +
  the privilege drop leaves `[CHOWN, DAC_OVERRIDE, SETGID, SETUID]` — all startup
  caps observation is blind to. Derived under the filesystem dimension's
  recommendation (`read_only:true` + `tmpfs:[/run/postgresql]`, via `run.read_only`
  + `run.tmpfs`): that adds **CHOWN** — the root-owned tmpfs socket dir must be
  chowned to the postgres user, a requirement invisible when caps are derived on
  a writable rootfs. Correctness check `correctness/postgres-caps.sh` asserts the workload
  passes **and** the server (PID 1) is non-root.
- **`homepage-fs.yaml`** — filesystem. **Validated end-to-end.** homepage serves
  under `--read-only` with `/app/config` writable (a persistent volume, supplied
  via `run.tmpfs` as a stand-in — not part of the minimum). Its one tmpfs need is
  `/app/.next/cache`: a bare dashboard `GET` serves without it, but Next.js image
  optimization `mkdir`s it on the first `/_next/image` request and errors when it
  can't — so `correctness/homepage.sh` triggers image optimization and checks the
  log. `/tmp` drop-tests as not required → `read_only:true,
  tmpfs:[/app/.next/cache]`.

## Adding a spec

Copy an existing spec, set the image + candidates, and write a correctness check that
checks *correctness* (the intended user, a working request, a passing workload)
— not just liveness. A container can be "healthy" and wrong.

## Multi-dimension profiles: derive under the siblings' recommendation

The dimensions of a profile are applied **as a unit**, so they interact — and a
dimension derived with its siblings at their *permissive defaults* can be wrong
once the whole profile is applied. Derive each dimension under the **recommended
values of its sibling dimensions** (not a permissive default, and not some extra
"hardened" config — exactly the siblings' own recommendation, so the result is
neither under- nor over-permissioned). The `run.read_only` + `run.tmpfs` fields
carry the filesystem dimension's recommendation into a capability drop-test.
(`run.tmpfs` doubles as a writable stand-in for a persistent **volume** the real
deployment provides — e.g. homepage's `/app/config` — always applied, never
counted in the derived tmpfs minimum.)

postgres is the worked example: caps derived on a writable rootfs give
`[DAC_OVERRIDE, SETGID, SETUID]`, but the profile also recommends
`read_only:true` + `tmpfs:[/run/postgresql]`, and the root-owned tmpfs socket dir
must be chowned → the real minimum is `[CHOWN, DAC_OVERRIDE, SETGID, SETUID]`.
Always finish by **verifying the combination**: run the workload under the union
of every derived dimension at once.

The capabilities direction is `run.cap_add`: every trial runs `--cap-drop ALL`
plus exactly these adds, so a non-caps dimension derives under the caps
dimension's recommendation. netdata is the worked example
(`netdata-fs.yaml`): its correctness check requires per-process metrics, which
require `SYS_PTRACE` granted — under docker's default cap set the fs minimum
would be derived under a grant the profile doesn't recommend. Rejected on a
`dimension: capabilities` spec (a caps spec drop-tests every granted cap as a
candidate).

## Research first — source the workload from upstream, don't invent it

Before writing a spec or a correctness check, spend a few minutes learning the
image from its own sources. A hand-guessed workload is the top cause of a wrong
derivation (the reverted mc-backup / minecraft profiles were hand-authored and
wrong; the faithful path is deriving from the image's real behavior). Three
places, each answering a different question:

1. **The image's entrypoint** — `docker-library/<image>/docker-entrypoint.sh`,
   or the project's own. This *predicts the capability candidates* before you
   run anything: it shows the privilege-drop shape (a `gosu`/`su-exec` re-exec
   → SETUID/SETGID; a master/worker fork; an in-process drop; a `setcap` +
   file-capability bridge → SETFCAP) and which directories it chowns → CHOWN /
   DAC_OVERRIDE / FOWNER. (mysql's DAC_OVERRIDE came straight from reading that
   its root-phase `find` must traverse a group-denied `/var/lib/mysql-files`.)

2. **The upstream's own tests** — `docker-library/official-images`
   `test/tests/<image>-basics/run.sh`, or the project's integration suite — for
   the *canonical* "prove it works" round-trip. Model the correctness check on
   that, not on a guess: it is the exercise the maintainers themselves trust
   (mysql's CREATE/INSERT/SELECT, rabbitmq's publish/consume, mongo's
   insertOne/countDocuments, memcached's set/get all came from there).

3. **The image, empirically** — `docker inspect` for `User` / `Volumes` /
   `Cmd`, then run it and check `/proc/1/status` uid, which ports it binds, and
   where it writes. This distinguishes *non-root by construction* (memcached,
   keycloak → zero-cap) from *root that still needs nothing* (jellyfin, minio)
   from *root that needs caps* — a distinction you cannot make from the tag
   name.

Only after this should you pick candidates and write the correctness check;
the seven rules below then keep that check honest.

## Correctness-check authoring rules

Eight rules a correctness check must follow, each learned from a real false
result during the container-security-profiles top-20 coverage build-out
(container-security-profiles#36) and the later privilege-audit work. Ignore one
and the derivation silently mis-derives — a false-required cap, a false-removable
cap, or a hang to timeout.

1. **Capture-then-match — never `curl … | grep -q` under `set -o pipefail`.**
   `grep -q` exits at the first match, the producer (curl/wget/`docker logs`)
   then takes SIGPIPE (exit 141), and pipefail makes the pipeline report
   *failure on a body that MATCHED*. It is masked whenever the output fits the
   pipe buffer, so small-response checks pass with the latent bug — it bites
   once the body outgrows the buffer (wordpress's 60 KB homepage; `docker logs`
   of any long-running container). Capture into a variable and match via a
   herestring (`grep -qE 'pat' <<<"$out"`) or a `case`. (A pipe *inside*
   `docker exec … sh -c '…'` is exempt — that nested shell has no pipefail, so
   its pipeline takes grep's exit — but don't rely on it at the outer level.)

2. **Exec probes as the service's user (`--user <u>`), never root.** An exec'd
   process runs in the target's bounding cap set, so a *root* probe's own needs
   pollute the minimum: rabbitmq derived a false DAC_OVERRIDE (reading the 0600
   `.erlang.cookie`) and FOWNER (rewriting `enabled_plugins`) until the probes
   ran as `rabbitmq`. Also its boot race — an exec'd root Erlang client races
   the entrypoint for `.erlang.cookie` creation and crashes the broker; gate on
   the service's own "ready" log line before the first exec.

3. **Write nothing inside the target.** A probe temp file (e.g. capturing a
   subscriber into `/tmp`) false-requires the filesystem dimension's `/tmp`
   candidate (mosquitto). Keep round-trips on stdout / in the service's own
   store.

4. **No external dependence in the trial loop.** Resolve/serve a
   *locally-answered* target, never one needing an upstream: pihole digs
   `pi.hole` (answered by FTL itself), adguard adds a rewrite
   `csd.test→127.0.0.1` first. An upstream in the loop turns a network blip
   into a false-broken verdict. Match the answer line, not the `:53` server
   line.

5. **Read `/proc` tool-free on minimal bases.** The uid assert must not assume
   `awk`/`cut`/`grep` exist — keycloak's UBI-micro base has no `awk`, which
   silently returned an empty uid and false-flagged root. Parse
   `/proc/1/status` in pure shell (`while read k v _; do [ "$k" = Uid: ] && …`).

6. **Assert the privilege drop, not just the response.** For master/worker
   images a dropped SETGID keeps *serving with root workers*; only a non-root
   worker-uid assert catches it (httpd, wordpress, nextcloud). A content check
   alone blesses silently-broken privilege separation.

7. **Pin the kernel posture for port-dependent caps.** NET_BIND_SERVICE only
   derives under `run.sysctls: [net.ipv4.ip_unprivileged_port_start=1024]` —
   Docker defaults it to 0 (all ports unprivileged), where a low-port bind
   reads falsely-removable (#340 item 5). The pinned posture is recorded in
   `run_config` so the profile is known valid only under it.

8. **Test the FEATURE, not the mechanism — software degrades gracefully.** A
   syscall returning EPERM under a dropped cap does NOT prove the feature that
   *usually* uses it is broken: production software often has a privilege-free
   fallback. So when you suspect a cap is load-bearing for some feature, drive
   the **feature** and check the observable OUTPUT (the chart collects, the
   round-trip completes) — do not conclude "needed" from an isolated mechanism
   test. The worked example is netdata's `SYS_ADMIN`: its `cgroup-network` helper
   *prefers* `setns(CLONE_NEWNET)` into each container's netns, which needs
   `SYS_ADMIN` and fails without it — an isolated `nsenter -n` test says "needed."
   But the feature (per-container network charts) still collects, via a host-side
   `veth` fallback, so `SYS_ADMIN` is genuinely removable. The isolated primitive
   said "needed"; the running deployment said "removable" — and **the running
   deployment is the authority.** (This rule cost two wrong published claims —
   first the un-caveated "removable", then an over-eager "you need it back" — before
   the live check settled it. Verify against the real deployment before publishing
   a privilege verdict.)
