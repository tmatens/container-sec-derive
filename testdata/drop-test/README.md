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

## Adding a spec

Copy an existing spec, set the image + candidates, and write a predicate that
checks *correctness* (the intended user, a working request, a passing workload)
— not just liveness. A container can be "healthy" and wrong.
