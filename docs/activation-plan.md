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

### 2. Build the scheduled deploy-check job
- Design: **csd#240**. A scheduled/on-demand job (mirror `derive-profiles.yml`)
  running `scripts/compose_derive.sh` over committed compose files, reporting the
  `deploy_check` verdict per service, failing on `under_permissioned`.
- **Do:** author `deploy-check.yml` + a manifest of `{compose_path, service,
  predicate}` for the services in scope. **Report-only first** (job summary),
  graduate to enforce.
- **Open decisions (#240):** which compose files / repos (the homelab services
  live in `dad/*` on Forgejo — decide how the GH runner reaches them); the
  per-service predicate library; report-vs-enforce.

### 3. Grow the predicate library (start: netdata)
- **The crux** (see `re-derive-at-deploy.md` → "The part re-derivation does *not*
  solve" and #240). One good predicate = deep, per-service, version-specific
  reverse-engineering **plus** this matched host.
- **netdata first** (scouting on #240): assert non-root uid **and** per-process
  metrics present (the `app.apps_plugin_*` charts carry data → proves
  `SYS_PTRACE`) **and** `ebpf.plugin` charts carry data (→ `SYS_ADMIN`, finally
  testable here because the matched host has `unprivileged_bpf_disabled=2` +
  AppArmor). netdata's own `apparmor:unconfined` narrows its match to the kernel
  BPF sysctls + this predicate.
- **Tier the library:** curated full-functionality predicates for the homelab
  set; the generic floor (`predicates/compose_generic.sh`) + a loud caveat for
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
  (`run_config`), **workload coverage** (the predicate), and the **derive
  environment** (host posture). All documented, none merely asserted.

## Map — where everything lives

| topic | where |
|---|---|
| the model, deploy check, 3 axes, predicate + env caveats | `docs/re-derive-at-deploy.md` |
| runner setup + the matched-host spec | `docs/self-hosted-runner.md` |
| scheduled deploy-check job design + netdata predicate scouting | csd#240 |
| config→capability study (the ~25 compose vars that change a profile) | csd#236 |
| rendered per-image catalog page (the honest reference a hint links to) | container-security-profiles#6 |
| the tools | `scripts/compose_derive.sh`, `scripts/derive_profiles.sh`, `scripts/drop_test.sh`, `.github/workflows/derive-profiles.yml` |
