# drop-test producer

`scripts/drop_test.sh` derives a **required minimum** by *removing each candidate
and verifying the container breaks without it*. It is csd's **experiment** layer,
complementary to the **observation** layer (the ig gadgets) — and, unlike a
gadget, it is not eBPF: it drives the container runtime and runs an
application-level correctness predicate.

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
`candidates` to drop-test, and a `predicate` script. The **predicate** is the
per-image correctness check — it returns 0 iff the container is *correct* (not
merely alive), reading the container name from `$DROP_TEST_CONTAINER`.

## Specs

- **`postgres-fs.yaml`** — filesystem. **Validated end-to-end**: dropping
  `/run/postgresql` makes postgres fail to start (socket dir), so it is required.
- **`netdata-caps.yaml`** — capabilities. **Validated end-to-end.** The predicate
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
  socket dir). Shared predicate `predicates/caddy.sh` (serves a `GET` on `:80`,
  via `docker exec` so no host ports are published).
- **`postgres-caps.yaml`** — capabilities. **Validated end-to-end.** Baseline
  `cap_drop:ALL` + the Docker default set on a fresh data dir (so initdb + the
  root→postgres `gosu` drop run); dropping each and re-verifying the workload +
  the privilege drop leaves `[CHOWN, DAC_OVERRIDE, SETGID, SETUID]` — all startup
  caps observation is blind to. Derived under the filesystem dimension's
  recommendation (`read_only:true` + `tmpfs:[/run/postgresql]`, via `run.read_only`
  + `run.tmpfs`): that adds **CHOWN** — the root-owned tmpfs socket dir must be
  chowned to the postgres user, a requirement invisible when caps are derived on
  a writable rootfs. Predicate `predicates/postgres-caps.sh` asserts the workload
  passes **and** the server (PID 1) is non-root.
- **`homepage-fs.yaml`** — filesystem. **Validated end-to-end.** homepage serves
  under `--read-only` with `/app/config` writable (a persistent volume, supplied
  via `run.tmpfs` as a stand-in — not part of the minimum). Its one tmpfs need is
  `/app/.next/cache`: a bare dashboard `GET` serves without it, but Next.js image
  optimization `mkdir`s it on the first `/_next/image` request and errors when it
  can't — so `predicates/homepage.sh` triggers image optimization and checks the
  log. `/tmp` drop-tests as not required → `read_only:true,
  tmpfs:[/app/.next/cache]`.

## Adding a spec

Copy an existing spec, set the image + candidates, and write a predicate that
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
