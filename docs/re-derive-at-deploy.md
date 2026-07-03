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
PREDICATE=testdata/drop-test/predicates/<svc>.sh \
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

## The part re-derivation does *not* solve: the predicate

Deriving against the real config removes the matching guesswork, but **not** the
need for a per-service correctness bar. "The container is still running" is not
"the container is correct" — netdata drops `SETUID`/`SETGID`, stays up, and runs
as **root**. The built-in `predicates/compose_generic.sh` (container stays
running) is a floor, and its weakness is deliberate and documented; a real
derivation should assert the intended posture — a request served, a non-root uid,
a passing workload — which is per-service knowledge, supplied via `PREDICATE`.

## Where it belongs

This is a **deploy/promote-time** step, not an authoring-time one: that's where
the exact image + config are in hand, and where the result can gate. It
complements — does not replace — the static authoring hint, which stays advisory
(a pointer that admits it can't see your runtime). The homelab deploy pipeline
(`deploy.sh` health-check + rollback) is the natural host: derive the minimum
against the just-built service and compare it to the compose's declared caps.

## Status

Prototype, **capabilities dimension**. Follow-ups: the filesystem dimension
(derive `read_only`/`tmpfs` from the service), a small library of per-service
correctness predicates, and the deploy-pipeline integration itself.
