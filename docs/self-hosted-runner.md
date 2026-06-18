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
- The **pinned `ig`** on `PATH` (the version in `internal/ig/ig.go` `PinnedIGVersion`).
  Install it the same way `integration.yml` does — download the per-arch tarball
  for that tag and verify it against `ig-pin/SHA256SUMS` before installing to
  `/usr/local/bin`.
- **Passwordless `sudo`** for the runner user (the smokes run `csd` under `sudo`
  for `CAP_BPF`/`CAP_PERFMON` + the docker socket).
- A kernel with **BTF** (`/sys/kernel/btf/vmlinux`) so `cap_capable` CO-RE can
  attach. The preflight step records and reports this.

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
