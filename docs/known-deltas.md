# Known deltas

Any time `csd observe`'s derived cap set differs from the bisected ground truth in `testdata/<image>/ground_truth.json`, the cause must be documentable here. v1 Correctness criterion 1 (PLAN.md §v1 success criteria) accepts "delta-with-cause" but rejects "the tool is non-deterministic." This file is where each cause lives, with reproduction steps.

## How to read an entry

Each delta has:

- **Reference image** — the `testdata/<image>/` the entry covers.
- **Bisected** — `caps` from `ground_truth.json`. The kernel is the validator; this is what the workload actually needs.
- **Compared against** — the other artifact: an observed run, an external curated profile, etc.
- **Delta** — set difference, both directions.
- **Cause** — why the two artifacts disagree. If the cause is in `csd`'s pipeline, link to the parser/aggregator path.
- **Reproduction** — exact commands to reproduce the delta on a privileged Linux host.
- **Disposition** — `documented` (intentional, lives here as an explanation), `bug` (a `csd` issue tracked elsewhere), `wontfix-by-design` (an architecture trade-off, see PLAN.md).

## Bisected vs. external curated profiles

These deltas are between `csd`'s bisected ground truth and a separate, externally-curated cap list. They exist before any `csd observe` run because the comparison artifact is a hand-maintained profile, not a `csd` output. They are recorded here so the reader knows the ground-truth value will differ from the curated one and why.

### postgres:16 — bisected `[DAC_OVERRIDE, SETGID, SETUID]` vs. compose-lint curated `[CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID]`

- **Reference image:** `testdata/postgres/` (`postgres:16@sha256:71e27bf60b…13ddf`).
- **Bisected:** `[DAC_OVERRIDE, SETGID, SETUID]`.
- **Compared against:** [compose-lint](https://github.com/tmatens/compose-lint) curated postgres profile, `[CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID]`.
- **Delta:** bisected is missing `CHOWN` and `FOWNER`.
- **Cause:** the `postgres:16` image is built with `/var/lib/postgresql/data` already owned by the `postgres` user. The entrypoint runs `chown -R postgres:postgres /var/lib/postgresql/data` and `chmod 0700` on first start, but those calls are no-ops on this image (uid/gid and mode already match), so they never enter the kernel paths that would fault for `CHOWN` or `FOWNER`. Other postgres images that ship a root-owned data dir, or any deployment that bind-mounts a host path with mismatched ownership, will need `CHOWN` and `FOWNER` in addition to the bisected three.
- **Reproduction:** `make ground-truth-postgres`, compare `testdata/postgres/ground_truth.json` against [compose-lint's `cap_profiles.yml`](https://github.com/tmatens/compose-lint).
- **Disposition:** `documented`. PLAN.md §v1 success criteria item 2 explicitly accepts this with a documented divergence rationale; this entry is that rationale. The bisection is correct for the default-config image; the compose-lint profile is correct as a more conservative recommendation that also covers the bind-mounted-data case.

### caddy:2 — bisected `[NET_BIND_SERVICE]` vs. an alternate-port workload that would bisect to `[]`

- **Reference image:** `testdata/caddy/` (`caddy:2@sha256:25cdc846…e562`).
- **Bisected:** `[NET_BIND_SERVICE]`.
- **Compared against:** a hypothetical `:8080`-binding workload variant that would bisect to `[]`.
- **Delta:** bisected has `NET_BIND_SERVICE`; alternate would not.
- **Cause:** the default-config caddy image runs as root and binds `:80`, which requires `NET_BIND_SERVICE`. An alternate Caddyfile listening on `:8080` removes the only privileged operation, but it would no longer reflect the default-config user experience.
- **Reproduction:** `make ground-truth-caddy` for the default; rebisecting with a swapped Caddyfile that listens on `:8080` would yield `[]`.
- **Disposition:** `wontfix-by-design`. Step 25 chose default-config faithfulness; the bisected `[NET_BIND_SERVICE]` is the recommended cap set for users running the default `caddy:2` image as-is.

### tailscale:stable — bisected `[]` (userspace mode) vs. TUN-mode that would need `NET_ADMIN`

- **Reference image:** `testdata/tailscale/` (`tailscale/tailscale:stable@sha256:dbeff02d…72a6`).
- **Bisected:** `[]`.
- **Compared against:** non-userspace tailscaled (`TS_USERSPACE=false`), which manages a TUN device and needs `NET_ADMIN`.
- **Delta:** bisected is empty; TUN-mode requires `NET_ADMIN`.
- **Cause:** the bisection driver's candidate set is the Docker default cap list, which does **not** include `NET_ADMIN`. If pointed at TUN-mode tailscaled, the driver would silently report a wrong "minimum" because it never adds `NET_ADMIN` to the trial cap set. The Makefile target hardcodes `TS_USERSPACE=true` to keep the bisection inside the candidate-set assumption.
- **Reproduction:** `make ground-truth-tailscale` for userspace mode. TUN-mode is intentionally not bisected; expanding `scripts/bisect_caps.sh`'s `DEFAULT_CAPS` to include `NET_ADMIN` (and an all-candidates-pass sanity check that fails loudly when the workload needs caps outside the candidate set) is a follow-up.
- **Disposition:** `wontfix-by-design` for v0.1. The userspace-mode bisection is sound and exercises the empty-set correctness of the driver. TUN-mode bisection waits on the candidate-set expansion.

## `csd observe` vs. bisected ground truth

This section will populate as observe-vs-truth runs land. Until `ig` is installed on a privileged host (see `docs/dev-setup.md`) and the runs happen, no entries here.

Expected first entries (anticipated, not yet observed):

- **postgres** — `csd observe` is expected to *also* miss `CHOWN`/`FOWNER` (matching the bisected three, not the compose-lint curated five) for the same reason: the entrypoint's `chown`/`chmod` no-op on the v16 image, so the kernel never sees a fault. If observed, this is a **non-delta** vs. the bisected truth — both csd and the kernel agree the workload doesn't need those caps.
- **postgres** — Step 11.1's smoke recorded SETPCAP and SYS_ADMIN attributed to `runc:[2:INIT]` past the 500ms init window. Step 21 added a comm-aware `runc:*` filter, so these should now be suppressed via `init_window_suppressed`, not surfaced as derived caps. If they leak through, the entry here will document the leak with the relevant `comm` value and a pointer to `main.go`'s init-filter path.
