# Self-hosted runner — extra live-BPF + hardware coverage

GitHub-hosted runners cover the baseline live tier (`integration.yml`), but they
give only one kernel and no real hardware devices. The `integration-selfhosted.yml`
workflow adds a **second real kernel, real `/dev` device detection, and the
closed-loop run on your own host** — when (and only when) a self-hosted runner is
registered. Until then it lies dormant (no `pull_request` trigger → no
perpetually-pending checks).

## Trust model (issue #116, Option A)

A runner that executes code with **root + BPF** must never run untrusted PR code
privileged, and csd PRs are agent-authored. So the workflow triggers **only on
`workflow_dispatch` + `schedule`**, both of which run against the **default branch
(`main`)** — already-reviewed, merged code. There is deliberately **no
`pull_request` trigger**.

**Use an ephemeral, on-demand runner.** You do not need a spare always-on box:
bring a runner up when you want the extra suite, trigger the workflow, then tear
it down. Run it on whatever you have — your desktop (often has a GPU for the
device test) or a VM/LXC on the homelab host (its own kernel isolates BPF test
churn from the production host).

## Host prerequisites

The runner host must have:
- **Docker** (the smokes spin containers).
- **Passwordless `sudo`** for the runner user (the smokes run `csd` under `sudo`
  for `CAP_BPF`/`CAP_PERFMON` + the docker socket).
- A kernel with **BTF** (`/sys/kernel/btf/vmlinux`) so `cap_capable` CO-RE can
  attach. The preflight step records and reports this.

The **pinned `ig`** (the version in `internal/ig/ig.go` `PinnedIGVersion`) is
**self-healed by the workflow**: an `Ensure pinned ig` step runs
`scripts/install_pinned_ig.sh` at the top of every job, which idempotently
downloads the per-arch tarball for the pinned tag, verifies it against
`ig-pin/SHA256SUMS`, and installs it to `/usr/local/bin` (skipping the download
when the pin is already present). So an `ig` lost to a reboot or a
`/usr/local/bin` wipe re-provisions itself on the next run instead of failing
every smoke with `IGMissing(31)` (issue #322). The `Preflight` step then
**asserts** the pinned `ig` is present and hard-fails with one clear line if it
isn't — no more six identical downstream failures.

To pre-provision `ig` on the host yourself (optional, e.g. baking it into a VM
image), run the same script from a repo checkout:

```sh
scripts/install_pinned_ig.sh   # needs curl/tar/sha256sum/dpkg + root or sudo
```

## Register an ephemeral runner (sketch)

From the repo's **Settings → Actions → Runners → New self-hosted runner**, follow
the per-OS download, then configure it with the label this workflow targets:

```sh
# In the runner directory, after ./config.sh with the repo URL + token:
./config.sh --url https://github.com/tmatens/container-sec-derive \
            --token <RUNNER_TOKEN> \
            --labels csd \
            --ephemeral --unattended
./run.sh        # processes one job, then exits (ephemeral)
```

`--ephemeral` makes the runner handle a single job and deregister — the
recommended posture for a privileged runner. The workflow targets
`runs-on: [self-hosted, csd]`, so the `csd` label is what wires it up.

## Run it

- **On demand:** Actions → *integration-selfhosted* → *Run workflow* (optionally
  set `duration`). Bring the runner up first (or have it `--ephemeral` waiting).
- **Scheduled:** the weekly cron fires automatically *if* a runner is online at
  that time; with an on-demand runner you'll typically just use dispatch.

Results land in the **job summary** (there's no PR to comment on): the recorded
kernel + the hardware-device PASS/FAIL/INFO lines.

## What it validates that hosted CI can't

- **A second kernel** — the whole smoke suite (`smoke_wsl2`/`fs`/`device`/`capadd`
  + `closed_loop`) on your host's kernel, catching BPF-attach differences the
  single hosted kernel hides (incl. the future LSM-BPF path, kernel ≥5.7).
- **Real hardware devices** — `scripts/smoke_device_hw.sh` tests whatever real
  `/dev` nodes are present (`/dev/dri`, `/dev/net/tun`, `/dev/kvm`, `/dev/fuse`,
  `/dev/snd`…), asserting csd records the open at its real path — beyond the
  hardware-free `/dev/null` gate the hosted device smoke uses.
- A foundation for **dogfooding** csd against the homelab's own containers from
  the same host.

A true multi-kernel *matrix* needs multiple runners/VMs on different kernels;
with one host you get one kernel per run — still a second data point beyond the
hosted runner. Spin the runner on different VM kernels over time to widen it.

## Profile re-derivation (`derive-profiles.yml`, compose-lint#360 step 4)

A second workflow targets the same `csd` runner: it keeps the external
`container-security-profiles` catalog current. On a schedule (and on dispatch),
`scripts/derive_profiles.sh` reads the catalog's `derivation/manifest.yaml` and,
per entry `method`, re-derives against each image's **current** digest —
`drop-test` entries via `scripts/drop_test.sh` (docker only), `bpf-observation`
entries via `csd --observe` under sudo. When a digest has moved and the
recommendation is unchanged it opens a catalog PR bumping `validated_image` +
`validated_date`; a **changed** recommendation is never auto-applied — it opens a
review issue instead.

Extra prerequisite beyond the smoke suite above: a repo secret **`CATALOG_PAT`**
— a fine-grained PAT scoped to `contents:write` + `pull-requests:write` on
`tmatens/container-security-profiles` **only** (it clones the catalog and opens
the PR/issue). No other secret is needed; git operations against `csd` itself use
the workflow's `GITHUB_TOKEN`. Like the smoke workflow it triggers only on
`schedule` + `workflow_dispatch` (never on PRs), so it always runs reviewed
`main` code.

## Matching the target's security posture (for MAC/BPF-class caps)

A drop-test can prove a capability *needed* (removing it broke something) but
**cannot prove one unneeded if the derive host never enforced the constraint**
(see `docs/re-derive-at-deploy.md`). So for `SYS_ADMIN` / BPF- / MAC-adjacent
capabilities to be trustworthy, the derive host must **match the deployment
target's security posture**. Run it as a **Debian 13 VM on the homelab host**
(`mini-server1`) — same hardware, isolated from production, and it matches by
construction.

### The spec to match (`mini-server1`, the deploy target)

| axis | value | notes |
|---|---|---|
| OS / kernel | Debian 13 (trixie), `6.12.x+deb13`, amd64 | same family = same cap/BTF behavior |
| `kernel.unprivileged_bpf_disabled` | `2` | BPF load needs `CAP_BPF`/`SYS_ADMIN` |
| `kernel.perf_event_paranoid` | `3` | perf/BPF-perf needs `CAP_PERFMON` |
| `kernel.kptr_restrict` | `1` | |
| **AppArmor** | **enabled** | the delta an Arch/permissive host misses |
| Docker | 29.x, overlayfs, systemd cgroup, cgroup v2, runc | default seccomp **and** apparmor applied to containers |

**A stock Debian 13 install matches most of this out of the box** — AppArmor is
enabled by default, the BPF sysctls are the Debian defaults, and Docker applies
its default seccomp + apparmor profiles. The permissive case that under-detects
is a host with AppArmor *off* (e.g. a default Arch box) or a non-matching kernel.

### Verify a candidate derive host against the target

```sh
uname -r; uname -m
for k in unprivileged_bpf_disabled perf_event_paranoid kptr_restrict; do
  printf '%s=%s\n' "$k" "$(cat /proc/sys/kernel/$k)"
done
cat /sys/module/apparmor/parameters/enabled   # want: Y
docker info --format '{{.SecurityOptions}}'    # want: apparmor + seccomp
```

Values must match the table (or the target host at derive time). If they don't,
treat `SYS_ADMIN`/BPF/MAC-class results as conservatively kept, not removable.

### Note on `apparmor:unconfined` services

A service whose compose sets `security_opt: [apparmor:unconfined]` (e.g. netdata)
opts *itself* out of AppArmor regardless of host, so for those the match narrows
to the kernel BPF sysctls + the caps themselves — and the correctness predicate
must still assert the BPF-backed feature (e.g. that `ebpf.plugin` charts carry
data), or `SYS_ADMIN` reads as a false over-grant on coverage grounds alone.
