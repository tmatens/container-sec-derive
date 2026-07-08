#!/usr/bin/env bash
# Install Docker Engine 29 and enable the containerd image store, then ASSERT
# both actually took — the validation lane for issue #180 TODO 3.
#
# Why this exists: csd shells out to the container CLI (`docker inspect` +
# `docker history` in the entrypoint cross-check, `docker inspect .Mounts` in the
# fs observer). Docker 29 makes the containerd image store the default on fresh
# installs, which changes `docker history` (layers can read `<missing>` for
# non-locally-built images) and reworks the local store. The hosted CI runner
# ships Docker 28 on the legacy overlay2 graphdriver store (confirmed by the
# integration.yml preflight), so nothing in CI exercises the store that triggers
# the degradation csd now handles gracefully. This script flips a runner to
# Docker 29 + the containerd store so the existing live-BPF smokes (caps/fs/…)
# run against it and turn "Docker >= 20.10" into a tested RANGE, not just a floor.
#
# It is idempotent: if the daemon already reports the target major AND the
# containerd store, it does nothing. It is DESTRUCTIVE to the host's Docker
# (replaces the engine, switches the image store so previously-pulled images are
# no longer visible) — intended for an ephemeral CI runner, NOT a dev machine.
#
# Usage (from anywhere): scripts/install_docker29.sh
# Override the target major for a future bump: DOCKER29_TARGET_MAJOR=30 scripts/...
# Needs: apt-based Ubuntu, curl, jq, and either root or passwordless sudo.
set -euo pipefail

TARGET_MAJOR="${DOCKER29_TARGET_MAJOR:-29}"

# Root (a provisioning shell) has no sudo; a CI runner user does. Mirror the
# same run-as helper install_pinned_ig.sh uses.
sudo_() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

server_ver() { docker version --format '{{.Server.Version}}' 2>/dev/null || true; }
store_driver() { docker info --format '{{.Driver}}' 2>/dev/null || true; }
# The containerd image store advertises the snapshotter plugin in DriverStatus;
# overlay2 (legacy graphdriver) never does. This is the authoritative signal,
# independent of the driver NAME (overlayfs vs overlay2).
store_is_containerd() {
  docker info --format '{{.DriverStatus}}' 2>/dev/null | grep -q 'io.containerd.snapshotter.v1'
}

if [[ "$(server_ver)" == "${TARGET_MAJOR}."* ]] && store_is_containerd; then
  echo "docker $(server_ver) already on the containerd image store; nothing to do"
  exit 0
fi

echo "== provisioning Docker ${TARGET_MAJOR} + containerd image store =="

# 1. Docker's official apt repository (Ubuntu). Keyring + arch-scoped source.
sudo_ apt-get update -qq
sudo_ apt-get install -y -qq ca-certificates curl jq
sudo_ install -m 0755 -d /etc/apt/keyrings
if [ ! -s /etc/apt/keyrings/docker.asc ]; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo_ tee /etc/apt/keyrings/docker.asc >/dev/null
  sudo_ chmod a+r /etc/apt/keyrings/docker.asc
fi
codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
arch="$(dpkg --print-architecture)"
echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${codename} stable" \
  | sudo_ tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo_ apt-get update -qq

# 2. Newest package version for the target major. madison prints
#    `docker-ce | 5:29.0.1-1~ubuntu.24.04~noble | <url>`; $3 is the epoch:version
#    string. Match ":29." so the epoch (5:) doesn't interfere.
pkg_ver="$(apt-cache madison docker-ce | awk -v maj="${TARGET_MAJOR}" '$3 ~ (":" maj "\\.") {print $3; exit}')"
if [ -z "${pkg_ver}" ]; then
  echo "ERROR: no docker-ce ${TARGET_MAJOR}.x candidate in the Docker apt repo for ${codename}/${arch}" >&2
  echo "       (Docker ${TARGET_MAJOR} may not be published for this release yet.)" >&2
  exit 1
fi
# The GitHub hosted runner ships the moby-* packages (moby-engine/-cli/-containerd
# /-runc), NOT docker-ce — and they own /usr/bin/docker, /usr/bin/containerd, etc.,
# which docker-ce + containerd.io would collide on. Remove the known conflicting
# packages first; best-effort so a runner image that drops one of them still works.
sudo_ apt-get remove -y -qq \
  moby-engine moby-cli moby-buildx moby-compose moby-containerd moby-runc \
  containerd runc >/dev/null 2>&1 || true

echo "installing docker-ce ${pkg_ver}"
# --allow-downgrades: the runner's preinstalled docker may be a newer patch of an
# OLDER major (e.g. 28.x) whose version string sorts above our pinned 29 candidate.
sudo_ apt-get install -y -qq --allow-downgrades \
  docker-ce="${pkg_ver}" docker-ce-cli="${pkg_ver}" \
  containerd.io docker-buildx-plugin docker-compose-plugin

# 3. Enable the containerd image store, merging into any existing daemon.json so
#    runner-provided config (registry mirrors, etc.) is preserved rather than
#    clobbered. On Docker 29 the store is the fresh-install default, but an
#    upgraded engine keeps the legacy store unless told otherwise — so set it
#    explicitly and the script also validates the toggle path itself.
daemon_json=/etc/docker/daemon.json
sudo_ install -m 0755 -d /etc/docker
tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
if sudo_ test -s "${daemon_json}"; then
  sudo_ cat "${daemon_json}" | jq '.features = ((.features // {}) + {"containerd-snapshotter": true})' >"${tmp}"
else
  echo '{"features":{"containerd-snapshotter":true}}' | jq . >"${tmp}"
fi
sudo_ install -m 0644 "${tmp}" "${daemon_json}"

# 4. Restart and wait for the socket to come back.
sudo_ systemctl restart docker
for _ in $(seq 1 30); do
  docker version >/dev/null 2>&1 && break
  sleep 1
done

# 5. Assert both conditions, hard-failing the job if either didn't take.
sv="$(server_ver)"
sd="$(store_driver)"
echo "docker server version: ${sv}"
echo "image store driver:    ${sd}"
docker info --format 'DriverStatus: {{.DriverStatus}}'
if [[ "${sv}" != "${TARGET_MAJOR}."* ]]; then
  echo "ERROR: expected Docker ${TARGET_MAJOR}.x, got '${sv}'" >&2
  exit 1
fi
if ! store_is_containerd; then
  echo "ERROR: containerd image store not active (driver='${sd}'); expected io.containerd.snapshotter.v1" >&2
  exit 1
fi
echo "OK: Docker ${sv} on the containerd image store"
