#!/usr/bin/env bash
# Workload exerciser for the tailscale reference image.
#
# Userspace-networking mode (TS_USERSPACE=true) only — no TUN device,
# no NET_ADMIN required. Exercises the daemon's local API: poll until
# `tailscale status` is responsive, then run `tailscale netcheck` to
# verify outbound connectivity diagnostics.
#
# Without an authkey the node stays Logged out; this is intentional —
# the workload validates daemon liveness and netcheck, not authentication.
# An authenticated end-to-end exercise belongs in v2 once we have a
# burner tailnet to drive against.
#
# Required env: TS_CONTAINER (target container name or id).
set -euo pipefail

: "${TS_CONTAINER:?TS_CONTAINER must be set}"

# Wait until tailscaled's local API is responsive. Without an authkey
# `tailscale status` exits non-zero (it considers Logged-out a non-zero
# state), so we accept either a successful exit or a "Logged out"
# message in stdout — both prove the local API is responsive.
deadline=$((SECONDS + 30))
until out=$(docker exec "${TS_CONTAINER}" tailscale status 2>&1) \
        || [[ "${out}" == *"Logged out"* ]] \
        || [[ "${out}" == *"Log in at"* ]]; do
    if (( SECONDS >= deadline )); then
        echo "tailscaled local API did not become responsive in 30s" >&2
        echo "${out}" >&2
        exit 1
    fi
    sleep 1
done

# netcheck — outbound DERP probe. Requires no caps in userspace mode.
docker exec "${TS_CONTAINER}" tailscale netcheck >/dev/null

# tailscale version — sanity that the CLI is callable.
docker exec "${TS_CONTAINER}" tailscale version >/dev/null

# tailscale debug daemon-logs — a final no-op-ish call against the local
# API. Bounded by --since=1s so output is small.
docker exec "${TS_CONTAINER}" tailscale debug daemon-logs --since=1s >/dev/null 2>&1 || true
