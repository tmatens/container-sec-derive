# Activation plan — automated derivation on the homelab

Everything for automated profile derivation and deploy-time capability checks is
**built and merged**. What remains is standing up one derivation host and
switching the automation on. This is the runbook + ordered next steps so any
session can pick it up cold.

## The one blocker: the derivation host

**Decided: a Debian 13 VM on `mini-server1`.** It matches the deploy target's
security posture by construction (so `SYS_ADMIN`/BPF/MAC-class caps derive
truthfully), isolates the privileged, container-churning drop-test from
production, costs nothing, and keeps private images/secrets in the homelab.

The exact spec to match and *why* is in
[`self-hosted-runner.md` → Matching the target's security posture](self-hosted-runner.md#matching-the-targets-security-posture-for-macbpf-class-caps).
A **stock Debian 13 install matches most of it by default** (AppArmor on, the BPF
sysctls, Docker's default seccomp+apparmor) — the posture that under-detects is a
host with AppArmor *off* (a default Arch box) or a non-matching kernel.

## Prerequisites (provision once)

1. **Build the VM** — stock Debian 13 (trixie) on `mini-server1` (KVM/libvirt).
   Verify it against the checklist in `self-hosted-runner.md` (`unprivileged_bpf_disabled=2`,
   AppArmor `Y`, Docker default seccomp+apparmor, BTF present).
2. **Install** — Docker (the normal way), passwordless `sudo` for the runner
   user, and — only for the `csd --observe` path, *not* the deploy check — the
   pinned `ig` (see `self-hosted-runner.md` → Host prerequisites).
3. **Register an ephemeral Actions runner labeled `csd`** (`self-hosted-runner.md`
   → Register an ephemeral runner).
4. **Add repo secret `CATALOG_PAT`** — fine-grained PAT, `contents:write` +
   `pull-requests:write` on `tmatens/container-security-profiles` **only**.

## Activation steps (in order, once the runner + secret exist)

### 1. Activate the catalog re-derivation loop
- Built + merged: `derive-profiles.yml` + `scripts/derive_profiles.sh` (csd#229).
- **Do:** dispatch `derive-profiles.yml` (`workflow_dispatch`). It re-derives the
  4 catalog profiles against their current digests and opens a catalog PR on
  drift (never auto-applies a *changed* recommendation). Confirm one green run,
  then it runs on schedule.
- **Proves:** the loop end-to-end on the matched host.

### 2. Build the scheduled deploy-check job — **BUILT**
- `deploy-check.yml` + `scripts/deploy_check.sh` + `deploy-check/manifest.yaml`
  (csd#240): on the `csd` runner, per manifest entry, clone the service's **live**
  `dad/*` compose from Forgejo and run `compose_derive.sh` against it → per-service
  `deploy_check` verdict in the job summary. **Report-only** (does not fail on a
  verdict; graduate to enforce by exiting on the worst).
- **Decisions settled:** the runner reads the live composes over HTTPS with a
  **read-only `FORGEJO_RO_TOKEN`** repo secret (a vendored copy would drift — the
  point is the *real* deployment). First scope = **netdata** (validated on the
  matched host). Deferred with documented reasons: **homepage** (binds `./config`
  owned by uid 1000 under `user:`+`read_only` — the cloned dir is root-owned on the
  derive host, an invocation-fidelity gap compose_derive must handle), **caddy**
  (`build:` image), **postgres** (no standalone service — embedded in immich's DB).
- **Remaining to activate:** add the `FORGEJO_RO_TOKEN` secret, then dispatch.

### 3. Grow the correctness check library (start: netdata)
- **The crux** (see `re-derive-at-deploy.md` → "The part re-derivation does *not*
  solve" and #240). One good correctness check = deep, per-service, version-specific
  reverse-engineering **plus** this matched host.
- **netdata — DONE** (csd#251, catalog#11; superseded the wrong 5→3 in
  csd#249/catalog#10). Final minimum **`[DAC_OVERRIDE, SETUID, SETGID, SYS_PTRACE]`**
  — drop **`SYS_ADMIN` only** (image ships no `ebpf.plugin`, so `ebpf=yes` is a
  no-op). **`SYS_PTRACE` is REQUIRED:** `apps.plugin` runs real-uid = the netdata
  user, so it needs it to read any process's `/proc/<pid>/io|fd`; without it every
  per-process metric collects as **0 (not null)** — a "has data (non-null)" check
  passed on all-zeros and a 5→3 attempt regressed production. The correctness check
  now requires a per-process `fds_open` to be **non-zero**, so the drop-test detects
  it. Deployed + verified at `dad/netdata` #32.
- **Tier the library:** curated full-functionality correctness checks for the homelab
  set; the generic floor (`correctness/compose_generic.sh`) + a loud caveat for
  the long tail. Never *enforce* on a generic-tier result.

## State of play (done, this session)

- **csd v0.7.0 released.** `compose_derive.sh` = derive-against-config →
  `deploy_check` verdict → gate exit codes → relative-mount resolution; proven
  live on real netdata.
- **Catalog:** 4 validated profiles (postgres, caddy, homepage, netdata), all
  schema 1.2 with `run_config`.
- **Consumption:** compose-lint enrichment made honest — per-service hints, a
  "can't see your runtime" caveat, **experimental-flagged + off by default**.
- **Fragility fully characterized** across its three axes: the **invocation**
  (`run_config`), **workload coverage** (the correctness check), and the **derive
  environment** (host posture). All documented, none merely asserted.

## Map — where everything lives

| topic | where |
|---|---|
| the model, deploy check, 3 axes, correctness check + env caveats | `docs/re-derive-at-deploy.md` |
| runner setup + the matched-host spec | `docs/self-hosted-runner.md` |
| scheduled deploy-check job design + netdata correctness check scouting | csd#240 |
| config→capability study (the ~25 compose vars that change a profile) | csd#236 |
| rendered per-image catalog page (the honest reference a hint links to) | container-security-profiles#6 |
| the tools | `scripts/compose_derive.sh`, `scripts/derive_profiles.sh`, `scripts/drop_test.sh`, `.github/workflows/derive-profiles.yml` |
