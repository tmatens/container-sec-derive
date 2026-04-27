# WSL2 + Docker Desktop

`csd` is built and tested on native Linux. WSL2 + Docker Desktop is a supported deployment target — recent WSL2 kernels ship BTF and the BPF features `ig` needs — but kernel coverage and feature availability vary across WSL2 builds, and we rely on a per-host smoke check rather than a portability promise.

When `csd observe` starts, it reads `/proc/version`. If the kernel reports `microsoft` or `WSL2`, it prints a one-line stderr note pointing at this file. The note is informational; it does not change behaviour.

## Quick smoke

```sh
make smoke-wsl2
```

This builds `csd`, runs `scripts/smoke_wsl2.sh`, and exits non-zero if any reference image fails. The script:

- Confirms the host is WSL2 (warns but continues on native Linux so the same command works as a portability check on a Linux dev box).
- For each of `postgres:16`, `caddy:2`, `tailscale/tailscale:stable`, and `csd-synthetic-exerciser:0.1`: starts the container, runs the matching `testdata/<image>/workload.sh`, observes for `DURATION` (default `30s`), writes a sidecar.
- Pass criteria differ per image:
  - **postgres / caddy / tailscale** pass when `csd` exits 0 and the sidecar reports `events_recorded + init_window_suppressed > 0`. This proves BPF attached and `cap_capable` events are flowing — the *cap set* may be empty (see `docs/known-deltas.md` for why postgres + caddy observe as `[]` against a curl/psql-only workload).
  - **synthetic** passes when the derived cap set is a superset of `testdata/synthetic/expected.json:expected_caps_minimum` (`CHOWN`, `NET_BIND_SERVICE`, `SETGID`, `SETUID`). The synthetic exerciser is csd's pipeline regression fixture; an empty observation here is a real csd bug, not a workload-shape artifact.

A failed image prints `FAIL <label>: …` and the matrix continues; the script exits non-zero with a summary. Run a subset with `ONLY=postgres,synthetic make smoke-wsl2`.

## Prerequisites on WSL2

- **Docker Desktop** with WSL2 backend, or Docker engine installed directly inside the WSL2 distro. `docker run` must work from your WSL2 shell.
- **`ig` binary** at `PinnedIGVersion` (currently `v0.51.0`) on `PATH`. Same install instructions as `docs/dev-setup.md` — the Linux amd64/arm64 tarballs work in WSL2.
- **`jq`** (the smoke script uses it for sidecar assertions).
- **`csd`** built locally (`make build`). The smoke target builds for you.

`CAP_BPF` and `CAP_PERFMON` are typically present under Docker Desktop because the WSL2 VM runs as root inside the lightweight VM. If `csd observe` exits with a permission error, run the smoke wrapper under `sudo -E` so the cap-bearing process inherits the right env.

## Known WSL2 specifics

This list is short on purpose — `csd` itself is host-agnostic, and the WSL2 axis is mostly "does the kernel expose what `ig` needs." Expand entries here as the contributor base reports gaps.

- **Kernel version.** WSL2 5.15+ ships BTF and `cap_capable` works against the standard tracepoint set. The `microsoft-standard-WSL2` build banner identifies the modern WSL2 image; the older `microsoft-standard` (5.10) banner is also detected by csd's note but has been observed to lack BTF on some host installs (see next bullet). Check with `uname -r` and update via `wsl --update` (PowerShell, host side) if the kernel is older than 5.15.
- **BTF availability.** `ig run trace_capabilities` requires kernel BTF. Most current WSL2 kernels ship `/sys/kernel/btf/vmlinux`; if it is missing, `ig` exits with a CO-RE relocation error before csd can attach. There is no in-tree workaround — the user must move to a WSL2 kernel build that includes BTF.
- **Docker Desktop port forwarding.** The caddy reference workload binds `127.0.0.1:18080:80` and `127.0.0.1:12019:2019` on the host side. With Docker Desktop's WSL2 backend the Windows host's `localhost` forwards into the VM, so the workload's `curl http://127.0.0.1:18080` works from inside the WSL2 distro but not necessarily from PowerShell on the Windows side. The smoke script runs entirely inside WSL2; no Windows-side network access is needed.
- **`/proc/version` detection.** `csd` matches `microsoft` or `wsl2` (case-insensitive) in `/proc/version`. If a future WSL build changes the banner format, csd will silently stop printing the note — the WSL2-detection helper is unit-tested (`TestLooksLikeWSL2`) so a banner change is caught at CI rather than in production.

## Reporting a gap

If `make smoke-wsl2` fails on a current WSL2 + Docker Desktop install:

1. Capture `uname -a`, `wsl --version` (PowerShell host), `docker version`, `ig version`, and the `FAIL <label>: …` line plus the failing image's `csd` log under `${TMPDIR}/<label>-csd.log`.
2. Open an issue with the captured artifacts and the WSL2 distro (`/etc/os-release`).
3. The remediation path is usually a kernel update (`wsl --update`) or a Docker Desktop reinstall — csd does not ship WSL2-specific code paths beyond the runtime note.
