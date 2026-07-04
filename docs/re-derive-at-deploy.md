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

## Status

Prototype, **capabilities dimension**. Follow-ups: the filesystem dimension
(derive `read_only`/`tmpfs` from the service), a small library of per-service
correctness checks, and the deploy-pipeline integration itself.
