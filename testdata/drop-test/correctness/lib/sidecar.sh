# Reusable sidecar-probe helpers for drop-test correctness checks against
# DISTROLESS target containers (no shell, no curl — so `docker exec <target>` has
# nothing to run). Source this from a correctness check:
#
#     . "$(dirname "$0")/lib/sidecar.sh"
#     sidecar_curl -sf http://localhost:3100/ready
#     body="$(sidecar_curl -s "http://localhost:3100/loki/api/v1/query_range?query=...")"
#
# HOW IT WORKS. A sidecar is a throwaway probe container run with
# `--network container:<target>`, so it SHARES the target's network namespace and
# reaches the service on `localhost:<port>` exactly as an in-container probe would.
# This is why we use it over a host-side probe of the container's bridge IP:
#   - it works for ANY target network mode uniformly — default bridge, a
#     user-defined network, an `--internal` network with no host route, or
#     `--network host` — with no per-mode IP handling;
#   - it does not depend on the drop-test host being the docker daemon host (works
#     under Docker Desktop / a remote `DOCKER_HOST`, where host->container-IP
#     routing does not exist);
#   - it never touches the target's filesystem, so it does not confound the
#     filesystem dimension (nothing is mounted into / exec'd inside the target).
# The cost is one extra pinned image; that is the deliberate trade.
#
# The probe image is a pinned, multi-arch curl. It is a TEST-ONLY image (never
# linked into csd); digest-pinned per the repo dependency policy. Override with
# CSD_PROBE_CURL_IMAGE if a check needs a different probe toolset.
#
# Requires DROP_TEST_CONTAINER (the target container name/id), which drop_test.sh
# exports before invoking the correctness check. The target must be RUNNING.

# curlimages/curl:8.11.1 — multi-arch manifest (amd64 + arm64 CI legs).
CSD_PROBE_CURL_IMAGE="${CSD_PROBE_CURL_IMAGE:-curlimages/curl@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69}"

# sidecar_run <image> [args...] : run a throwaway probe container in the target's
# network namespace. Prints the probe's stdout; returns its exit code.
sidecar_run() {
    : "${DROP_TEST_CONTAINER:?DROP_TEST_CONTAINER must be set}"
    local image="$1"; shift
    docker run --rm --network "container:${DROP_TEST_CONTAINER}" "$image" "$@"
}

# sidecar_curl [curl-args...] : curl the target over localhost, from a sidecar.
sidecar_curl() {
    sidecar_run "$CSD_PROBE_CURL_IMAGE" "$@"
}
