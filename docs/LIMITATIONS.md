# Inherent limitations

This document records the **structural** limits on what `csd` can derive — the
things it *cannot* tell you and why — as distinct from the not-yet-built backlog
in [ROADMAP.md](../ROADMAP.md). These are not bugs, and most are not fixable by
adding an Inspektor Gadget gadget. They are properties of dynamic observation and
of the signals the kernel/IG expose.

Each limitation is already surfaced at runtime (non-strippable caveats, confidence
levels, partial-decomposition flags). This page exists so a user or contributor
can find them in one place instead of rediscovering them. Tracked in **issue #152**.

## 1. Dynamic-only observation — the floor under every observer

`csd` observes **one run** and infers from what the workload exercised. Anything
the workload does not do during the observation window is invisible — to *every*
observer, including all shipped ones (`caps`, `fs`, `devices`, `privileged`,
`capadd`, `egress`):

- a write path only hit on an error or rare-feature branch → missing from `tmpfs:`
- a capability only used under specific load or kernel version → dropped
- an egress destination only contacted during failover → absent from the allowlist

**Why it can't be fixed:** this is intrinsic to dynamic tracing. It can only be
mitigated — by driving a representative workload (`--workload`), by the confidence
rubric, and by the planned steady-state / target-exited-early coverage signals. It
is **not** a correctness proof and never will be.

**How it's surfaced:** the canonical, non-strippable sidecar `Caveat`:

> "BPF-observed profiles reflect only the paths the workload exercised. Not a correctness proof."

**Consequence to keep in mind:** this limitation produces *under*-permissive
output that looks complete. A derived profile is a floor on what was seen, not a
ceiling on what the workload needs. Treat it as a strong starting point to review,
not a finished policy to enforce blind.

## 2. The MAC blind spot — `privileged` decomposition is permanently partial

`--observe privileged` recovers the **caps + devices** half of `privileged: true`
but structurally **cannot observe the AppArmor/seccomp (`security_opt`)
dimension**. There is no built-in IG denial gadget at the pinned IG version (or the
current latest), so relaxed/unconfined MAC use is unobservable. The decomposition
is therefore flagged **partial** — "drop `privileged: true`" covers only two of its
three dimensions.

**Why it can't be fixed (today):** same wall as limitation 4 below — no built-in
gadget exposes the signal. Delivering it would require a custom csd-authored gadget
(a change to the locked "built-in gadgets, subprocess only" posture) or upstream IG
support. The IG-gadget survey for v0.3 (issue #92) confirmed no denial gadget at the
pin; the latest IG release adds nothing that closes it.

**How it's surfaced:** the `partial: true` flag on the `privileged_decomposition`
sidecar block, a header on every text formatter, a stderr advisory, and the
non-strippable `PrivilegedSecurityOptCaveat`:

> "AppArmor/seccomp (security_opt) not observed; this decomposition covers caps + devices only. Verify the workload does not rely on unconfined MAC before dropping privileged: true."

**Consequence to keep in mind:** this is the inherent gap that most easily bites a
real user, because it ships **today** behind a confident-sounding "drop
`privileged: true`" headline. A workload that relies on relaxed MAC will break if
the recommendation is trusted without verifying the unobserved dimension.

## 3. Inverted-risk derivations — egress (and the planned host-network validator)

For `caps` / `devices` / `fs`, the dynamic-only limitation (1) produces
*over*-permissive output — you grant slightly too much, which is relatively safe.
For **egress allowlists the failure mode inverts**: a destination `csd` did not
observe becomes a **default-DROP that blocks the app in production**. Same
underlying limitation, but the config type makes a miss *actively harmful* rather
than merely loose.

**Why it matters as a class:** any observer whose output is a *default-deny*
enforcement artifact inherits this property. The planned v0.6 host-network
necessity validator is the next example. Such observers should default to **LOW
confidence when no `--workload` is supplied** and carry a non-strippable
completeness caveat, by design.

**How it's surfaced:** the non-strippable `EgressCaveat`, and confidence forced to
**low** when no workload is supplied (issue #136):

> "Egress allowlist reflects only destinations contacted during observation. A destination the workload did not exercise will be BLOCKED by these rules — verify completeness before enforcing default-deny."

## 4. Signal-blocked dimensions — no built-in gadget exists

Two intended dimensions are blocked because no built-in IG gadget exposes the
signal at the pinned version (or the current latest):

- **Docker socket API scoping** (`/var/run/docker.sock`) — **issue #110 (open).**
  `docker.sock` is `AF_UNIX` and the API is plaintext HTTP: `trace_tcp` / `tcpdump`
  are TCP/IP only, `trace_ssl` is TLS-only, and `trace_open` misses
  `connect()`-based socket use. See [ROADMAP.md](../ROADMAP.md) §v0.4.
- **AppArmor/seccomp denials** (`security_opt`) — the same wall, applied to a
  shipped feature; see limitation 2.

**Why it can't be fixed (today):** delivering either would require a custom
csd-authored IG gadget — a change to the locked "built-in gadgets, subprocess only"
posture (PLAN.md Decisions 5/7) — or upstream IG support. They are held until one of
those exists. #110 remains the live tracker for the socket-specific signal survey.

## What is *not* an inherent limitation

So this list is not over-counted, two commonly-assumed "gaps" are deferred by
**choice**, not blocked:

- **seccomp profile generation** — already solved by `oci-seccomp-bpf-hook` and
  IG's `advise seccomp-profile`; `csd` will integrate or link rather than reinvent.
- **LSM-BPF capability hook** (`SEC("lsm/capable")`) — waits only on distro kernel
  support (`CONFIG_BPF_LSM=y`, kernel ≥ 5.7). A clean upstream contribution when
  support justifies it.

Both are tracked in [ROADMAP.md](../ROADMAP.md) as planned work, not walls.
