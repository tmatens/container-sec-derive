# App-tier verification

Deriving a container's minimum caps is a per-container operation. But a real
service — immich, say — is several containers working together, and **"the DB is
correct in isolation" is not "immich still works."** This doc is the model for
closing that gap, and its worked example.

## Caps are composition-independent; correctness is not

A container needs a capability for what *its own* processes do — init (chown a
data dir), a privilege drop (`setuid`/`setgid` via gosu), a specific privileged
syscall. None of that depends on whether its network peers are up. So a
container's **capability minimum is the same in isolation as in the full stack**,
and the per-container drop-test (`scripts/drop_test.sh`) derives it faithfully
one container at a time.

What *does* depend on the composition is the **correctness check**. A container
can be split into two kinds:

| kind | example | correct in isolation? |
|---|---|---|
| **leaf** | postgres, redis | yes — serves with no peers |
| **dependent** | immich-server, immich-machine-learning | no — needs its `depends_on` up |

A leaf derives and verifies standalone. A dependent tier can't even reach a
passing baseline without its dependencies, so its correctness — and the proof
that a *sibling's* hardening didn't break it — only exists at the level of the
whole service.

Note also there is no single "immich profile": the catalog decomposes per **image**
(`{postgres, valkey, immich-server, …}`), and a consumer matches each *service* to
its image's profile.

## Two-tier correctness

1. **Per-iteration (the drop-test loop).** A cheap, targeted check, run ~15× per
   derivation (leave-one-out). It only needs to detect the cap-relevant breakage
   fast — nothing more.
2. **App-tier verify (once, under the derived minimum).** Bring up the *whole
   stack* with the hardening applied and confirm the service does its real job.
   This is where a multi-container service is actually validated: **test the app
   tier after every container hardening.**

`scripts/apptier_verify.sh <compose.yml> <verify.sh>` is tier 2: it `docker
compose up`s a stack whose compose already encodes the caps you're validating,
runs a service-level check, and tears down.

## Pull the pieces; don't run the whole upstream suite

The best correctness coverage is the upstream project's own tests — workload
coverage is what bounds derivation validity (the netdata `SYS_PTRACE` lesson). But
running a project's full e2e suite whole is the wrong tool here: immich's is a
pnpm-monorepo Vitest/Playwright suite that **builds the server from source** and is
coupled to immich's CI. It tests *immich's code*, not "does a hardened deployment
of the released images work."

So **reuse the valuable pieces** — the upstream **fixtures** and the **real API
contract** — with a lightweight driver:

- immich's e2e `test-assets` gives real photos; a small committed synthetic JPEG
  (`testdata/apptier/immich/fixture.jpg`) is enough for an upload test, and avoids
  the 237 MB submodule.
- immich's `src/specs/server/**` tests show the exact API calls; we drive them
  directly with `curl` — no SDK, no Vitest, no source build.

For **capability** correctness this loses nothing: the DB's caps are all
init/privilege-drop, exercised by *any* real ingest→store→retrieve. The suite's
exhaustive functional breadth would matter for a hardened application tier, but
immich-server already runs `cap_drop: ALL` with no adds.

## Worked example: immich's postgres

`testdata/apptier/immich/` is the released stack (immich-server `v2.7.5` + valkey +
the custom postgres) with the **derived** DB hardening applied — `cap_drop: ALL`
plus `[CHOWN, DAC_OVERRIDE, SETUID, SETGID]`, i.e. the declared set **minus
FOWNER** (the deploy-check verdict for that image). `verify.sh` drives the API:
admin sign-up → login → upload the fixture → read it back → metadata search.

Verified on the BPF box (2026-07-04):

| DB hardening | DB | immich app-tier |
|---|---|---|
| `drop FOWNER` (derived minimum) | healthy | **PASS** — all five API steps succeed |
| `drop SETUID` (over-hardened) | unhealthy (`failed switching to "postgres"`) | **FAIL** — server never starts |

So the app-tier check both **confirms** the derived hardening (FOWNER really is
removable, against immich's real usage — not just the drop-test's narrow workload)
and **discriminates** (an over-hardening that breaks the DB's privilege-drop makes
immich fail to come up). That second row is why this tier exists.

```
scripts/apptier_verify.sh \
  testdata/apptier/immich/docker-compose.yml \
  testdata/apptier/immich/verify.sh
# → apptier: PASS — the service works with the applied hardening
```

## Running it / limits

- **Live only.** Needs `docker` + the `docker compose` v2 plugin (the drop-test
  itself only uses raw `docker run`) and a network pull (immich-server is ~3 GB).
  It is on-demand (`make apptier-immich`), not a per-PR gate.
- The stack uses the **released** images, so it matches the deployment; it does not
  build immich from source.
- A convenience for pointing an upstream suite at your own stack, if you ever want
  the full thing: immich's Vitest **skips its own `docker compose up` when
  `http://127.0.0.1:2285/api/server/ping` is already reachable** — bring up the
  hardened stack first and its suite runs against it.

## Not yet built: in-stack derivation for dependent tiers

This verifies a *leaf's* hardening at the service level. Actually **deriving** a
dependent tier's caps (immich-server, ML) needs the inverse harness: bring up its
`depends_on` as un-drop-tested supporting cast, drop-test the target within the
running stack, with correctness = the real app function. That's a larger,
separate piece; for now dependent tiers that already run `cap_drop: ALL` need no
derivation, and leaf hardening is validated here.
