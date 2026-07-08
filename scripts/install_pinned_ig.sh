#!/usr/bin/env bash
# Install the pinned Inspektor Gadget `ig` binary, verified against the committed
# supply-chain pin (ig-pin/SHA256SUMS), to /usr/local/bin.
#
# This is the single source of truth for "get the right ig onto this host's PATH":
# the hosted live-BPF CI (integration.yml), the self-hosted runner lane
# (integration-selfhosted.yml), and a human provisioning a self-hosted runner all
# call it, so the four contexts can never drift on version or verification.
#
# It is IDEMPOTENT and self-healing: if `ig version` already reports the pinned
# release it does nothing, so it is cheap to run at the top of every job. That is
# the durable fix for issue #322 — a self-hosted runner that lost its ig (reboot,
# /usr/local/bin wipe) re-provisions itself on the next run instead of failing
# every smoke with IGMissing(31).
#
# Version comes from internal/ig/ig.go PinnedIGVersion (the same awk anchor the
# workflows use). No "latest" anywhere; a digest miss is a hard failure.
#
# Usage: run from the repo root.
#   scripts/install_pinned_ig.sh
# Needs: curl, tar, sha256sum, dpkg (for arch), and either root or passwordless
# sudo to write /usr/local/bin.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

ig_go="internal/ig/ig.go"
sums="ig-pin/SHA256SUMS"

# Extract the pin with the same start-of-line-anchored awk the workflows use, so
# a prose mention of the constant in a comment can't match first (see ig.go).
IG_VERSION="$(awk -F'"' '/^[[:space:]]+PinnedIGVersion[[:space:]]+=/ {print $2; exit}' "$ig_go")"
if [ -z "${IG_VERSION}" ]; then
  echo "ERROR: could not extract PinnedIGVersion from ${ig_go}" >&2
  exit 1
fi

# Idempotency + self-heal decision: parse the first whitespace token of
# `ig version` exactly as internal/ig CheckIGVersion does. Already-pinned → done.
current=""
if command -v ig >/dev/null 2>&1; then
  current="$(ig version 2>/dev/null | awk 'NR==1{print $1}')"
fi
if [ "${current}" = "${IG_VERSION}" ]; then
  echo "ig ${IG_VERSION} already installed (pinned); nothing to do"
  exit 0
fi
if [ -n "${current}" ]; then
  echo "ig ${current} present but pin is ${IG_VERSION}; reinstalling"
else
  echo "ig not found on PATH; installing pinned ${IG_VERSION}"
fi

# ig ships per-arch tarballs; pick by the host's arch so an arm64 host installs
# arm64 ig. dpkg's arch names (amd64/arm64) match ig's artifact naming exactly,
# and ig-pin/SHA256SUMS carries both digests.
arch="$(dpkg --print-architecture)"
artifact="ig-linux-${arch}-${IG_VERSION}.tar.gz"
url="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/${artifact}"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

curl -fsSL "${url}" -o "${tmp}/${artifact}"

line="$(grep -E "  ${artifact}\$" "${sums}" || true)"
if [ -z "${line}" ]; then
  echo "ERROR: no digest for ${artifact} in ${sums} — bump PinnedIGVersion and run scripts/refresh-ig-pin.sh" >&2
  exit 1
fi
( cd "${tmp}" && printf '%s\n' "${line}" | sha256sum -c - )

tar -C "${tmp}" -xzf "${tmp}/${artifact}" ig

# Root context (a provisioning script) doesn't have sudo; a CI runner user does.
if [ "$(id -u)" -eq 0 ]; then
  install -m 0755 "${tmp}/ig" /usr/local/bin/ig
else
  sudo install -m 0755 "${tmp}/ig" /usr/local/bin/ig
fi

ig version
