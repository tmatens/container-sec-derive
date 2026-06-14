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

Captured 2026-04-27 against `ig v0.51.0` on a Linux 6.17 host with the Step 21 `runc:*` comm filter and Step 19 `capable:false` drop both shipped. Each entry follows the six-field structure above; reproduction commands assume the wrappers from PLAN.md §Workload-shape limits.

### postgres:16 — observed `[]` vs. bisected `[DAC_OVERRIDE, SETGID, SETUID]`

- **Reference image:** `testdata/postgres/` (`postgres:16@sha256:71e27bf60b…13ddf`).
- **Bisected:** `[DAC_OVERRIDE, SETGID, SETUID]`.
- **Compared against:** `csd observe --container <postgres> --duration 60s --workload testdata/postgres/workload.sh`. Sidecar: 1428 events recorded, 509 attributed to the target replica, **509 suppressed by the runc:* comm filter**, `distinct_comms = 0`, `capabilities = []`, confidence `low`.
- **Delta:** observation derives the empty set; bisection derives three caps. Observation undershoots.
- **Cause:** every `capable=true` event for the postgres container fired from a `runc:[*:INIT]` comm — the entrypoint's `gosu` user-switch (SETUID/SETGID) and DAC_OVERRIDE on `/var/lib/postgresql/data` happen inside the runc init exec session, and each `docker exec psql` in the workload spawns a fresh `runc:[*:INIT]` that triggers another ~80 cap_capable=true events. Step 21's `runc:*` filter is correct to suppress these as init noise (otherwise SETPCAP/SYS_ADMIN from runc would leak into derived caps). Postgres at runtime simply does not invoke `capable()` for SQL ops — the privileged paths it needs are exercised once, in init, under runc attribution. The kernel never asks `capable()` outside that window during steady-state queries. The acceptance gate held: confidence `low` (event count in 100-999, distinct_comms < 2) blocks this run from passing the `compose-lint-profile` ≥moderate floor, so it cannot ship as a profile.
- **Reproduction:** `bash /tmp/observe-postgres.sh` (wrapper template in PLAN.md §Workload-shape limits). Cross-check raw NDJSON: 1839 total events for the container, 714 capable=true, all attributable to `runc:[1:CHILD]`/`runc:[2:INIT]` comms; 1125 capable=false correctly dropped by Step 19.
- **Disposition:** `wontfix-by-design`. Documents the inherent limit of BPF cap_capable observation for entrypoint-heavy images. PLAN.md §Foot-guns "Attach-window blindness" names this as the canonical example. Mitigation path is bisection, which already produces the correct ground truth.

### caddy:2 — observed `[]` vs. bisected `[NET_BIND_SERVICE]`

- **Reference image:** `testdata/caddy/` (`caddy:2@sha256:25cdc846…e562`).
- **Bisected:** `[NET_BIND_SERVICE]`.
- **Compared against:** `csd observe --container <caddy> --duration 60s --workload testdata/caddy/workload.sh`. Sidecar: **0 events recorded**, `replicas_observed = 0`, `capabilities = []`, confidence `low`. Raw NDJSON dump (`ig run trace_capabilities --timeout 60`) over the same window: 0 events for the container — confirms no csd-side filter artifact.
- **Delta:** observation derives the empty set; bisection derives `NET_BIND_SERVICE`.
- **Cause:** `bind(:80)` is the only operation in the caddy lifecycle that triggers `cap_capable(CAP_NET_BIND_SERVICE)`. It happens inside the caddy process, not under runc attribution — but it happens once, during initial container start, **before `ig` finishes loading its BPF programs and attaches**. The wrapper sleeps 2 seconds between `docker run -d` and `csd observe` launch (a smaller value just races worse); within that window caddy has already bound. The 60-second observation window then captures only steady-state caddy serving curl requests, plus one `docker kill --signal=SIGUSR1` reload — none of which re-enter `cap_capable()` because the listener is already bound and the reload reuses the existing process. The workload also avoids `docker exec`, so no fresh `runc:[*:INIT]` events arrive either. Net: 0 events, 0 observed caps.
- **Reproduction:** `bash /tmp/observe-caddy.sh` for the csd run; `bash /tmp/capture-caddy-raw.sh` for the raw NDJSON dump.
- **Disposition:** `wontfix-by-design`. This is a sharper case of the postgres pattern — there `runc:*` events at least proved ig was attached and filtering correctly; here observation is silent because the cap-using operation happened pre-attach and never recurred. PLAN.md §Foot-guns "Attach-window blindness" generalizes both. A future restart-aware observer (`--follow-restart` plus a "restart the container after ig attaches" mode) would close this gap; not in v0.1 scope.

### tailscale:stable — observed `[NET_RAW]` vs. bisected `[]`

- **Reference image:** `testdata/tailscale/` (`tailscale/tailscale:stable@sha256:dbeff02d…72a6`).
- **Bisected:** `[]`.
- **Compared against:** `csd observe --container <tailscale> --duration 60s --workload testdata/tailscale/workload.sh`. Sidecar: 568 events recorded, 461 attributed to the target replica, 457 suppressed by the runc:* filter, **4 capable=true events from `comm = tailscale` for `CAP_NET_RAW`**, `capabilities = [NET_RAW]`, confidence `low`.
- **Delta:** observation derives `[NET_RAW]`; bisection derives the empty set. Observation overshoots relative to bisection — but in this case observation is the more informative signal.
- **Cause:** tailscale's `netcheck` opens a raw ICMP socket (`SOCK_RAW`, IPPROTO_ICMP) for low-latency DERP probing when `CAP_NET_RAW` is held. When the cap is dropped, the kernel returns `-EPERM` on `socket()` and tailscale falls back to UDP probes — netcheck still completes, the workload still passes. Bisection's "drop the cap, see if the workload fails" mechanic therefore reports NET_RAW as not required (the fallback is always available). Observation captures the binary's *attempt* on the privileged path, which is the more accurate description of the cap surface tailscale actually uses when it is allowed to. This is an opportunistic-cap pattern: the binary always tries the privileged path first, only falls back when denied. Bisection's structural limit is that it cannot distinguish "cap is required" from "cap improves the path the binary chose."
- **Reproduction:** `bash /tmp/observe-tailscale.sh`.
- **Disposition:** `documented`. Both observations are correct, and they answer different questions. Bisection answers "what is the minimum set the workload provably needs?" Observation answers "what is the cap surface the binary actually exercises when allowed?" The compose-lint contribution gate on `csd observe` profiles already requires confidence ≥moderate; this `low`-confidence run cannot ship as a recommendation. A user who wants the strictly-minimum tailscale profile uses the bisected `[]`; a user who wants tailscale to take its preferred fast path adds `NET_RAW` deliberately. PLAN.md §Foot-guns "Opportunistic-cap divergence" generalizes the pattern; future work on a `--required-vs-used` annotation in the sidecar would surface this distinction in-band rather than only in this doc.

## `csd --observe fs` writable-path observations (v0.2)

The v0.2 read-only-filesystem observer (`--observe fs`) inherits the same
attach-window caveat the capability observer has: `ig run trace_open` only
sees opens that fire *after* its BPF programs load, so writes a container
performs during image/entrypoint init are invisible. There is no bisection
analog for writable paths (you cannot "drop a path and see if the workload
fails"), so the fs ground truth is an exercised-write expectation, validated
by `scripts/smoke_fs.sh` in `integration.yml`.

### synthetic exerciser — deterministic gate `[/csd-exerciser-target]`

- **Reference image:** `testdata/synthetic/` (`csd-synthetic-exerciser:0.1`); ground truth `testdata/synthetic/fs_expected.json`.
- **Expected:** `csd --observe fs` derives a `writable_paths` entry for `/csd-exerciser-target` (disposition `tmpfs_candidate`; the container declares no volume, so the file's parent `/` is an unbacked rootfs write and `fs_recommendation` is `read_only: true` + `tmpfs: [/]`).
- **Why deterministic:** the exerciser opens `/csd-exerciser-target` with `O_CREAT|O_WRONLY|O_TRUNC` and `write(2)`s a byte every cycle (`exerciser.c`), so trace_open records a write-intent open continuously post-attach — unlike the cap gate it needs no sysctl. This is the **sole hard gate** of the fs smoke: an empty observation here is a real csd pipeline bug.
- **Confidence:** `low` by design (a single sparse write path); this run is a pipeline attach+record regression check, never a contributable profile.

### postgres / caddy / tailscale — informational

- **Expected:** sparse or empty post-attach write sets. postgres's data-dir and socket/lock writes happen during entrypoint init (`initdb`, `gosu` user-switch) before ig attaches; caddy writes its config/state at startup; tailscale (userspace mode) keeps state in memory. Whatever each *does* write post-attach during its workload is reported informationally by `scripts/smoke_fs.sh` and never fails the build — the same workload-shape caveat the capability observer carries above. A user wanting a trustworthy read_only/tmpfs profile for these images runs a longer window with a workload that exercises steady-state writes, and reviews the `low`-confidence sidecar before contributing.
- **Disposition:** `documented`. The fs observer is correct; the limit is workload coverage + the attach window, identical in shape to the capability deltas above. A future restart-aware mode (attach ig, then `docker start`) would close the attach-window half for both observers.
