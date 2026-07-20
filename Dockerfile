# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
#
# csd container image — bundles the csd Go binary plus the vendored
# Inspektor Gadget (ig) binary pinned by ig-pin/SHA256SUMS.
#
# Build: docker buildx build --platform linux/amd64,linux/arm64 -t tmatens/container-sec-derive:dev .
# Run:   docker run --rm \
#          --pid=host \
#          --cap-drop=ALL --cap-add=BPF --cap-add=PERFMON \
#          -v /var/run/docker.sock:/var/run/docker.sock:ro \
#          tmatens/container-sec-derive:dev --container <id>
#
# The image runs as UID 0 by design. csd's entrypoint requests
# CAP_BPF + CAP_PERFMON to attach the eBPF probe; under the default
# Linux ambient/inheritable capability rules, an unprivileged UID
# inside the container would not inherit those capabilities even when
# the container itself has them. Running as root inside the container
# is consistent with PLAN.md §Tool posture (csd is root-equivalent on
# the host by design — the container security boundary plus
# --cap-drop=ALL minus the specific BPF/PERFMON caps is the security
# envelope, not an unprivileged UID).

# --- builder: compile csd + fetch and verify the vendored ig binary ---
# No `--platform=$BUILDPLATFORM`: the legacy (non-buildx) Docker
# builder errors on an empty $BUILDPLATFORM. buildx will set
# TARGETOS / TARGETARCH per matrix arch in CI; for a local single-arch
# build, the defaults below match the host. Cross-arch CI builds use
# native runners per-arch (per compose-lint's pattern) — emulation in
# the builder stage is never the hot path.
FROM golang:1.26-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS builder

# IG_VERSION must match PinnedIGVersion in internal/ig/ig.go; the `make image`
# target extracts it via awk and passes it through. The committed
# ig-pin/SHA256SUMS lists artifacts for exactly this version, so a
# mismatch fails the sha256sum -c step below rather than silently
# building against a different IG release.
ARG IG_VERSION=v0.51.0
# TARGETARCH must be passed explicitly via --build-arg by both CI
# (matrix arch per leg of the build) and the Makefile (host arch via
# `go env GOARCH`). No default: a Dockerfile-level default for
# TARGETARCH overrides BuildKit's auto-populated value, which would
# silently download the wrong-arch ig binary on cross-arch builds —
# the same bug the per-arch CI matrix caught on the first run.
ARG TARGETARCH
ARG TARGETOS=linux
# CSD_VERSION is injected by the Makefile / release pipeline as a
# git-describe-style string; it surfaces through `csd --version`.
# Defaults to "dev" so a plain `docker build .` produces a runnable
# image even outside the release path.
ARG CSD_VERSION=dev

WORKDIR /src

# Copy go.mod / go.sum first for layer caching. csd has no third-party
# runtime deps yet (CLAUDE.md §Dependency pinning), so go.sum may be
# empty — the COPY still succeeds.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# Build csd as a fully static binary. CGO_ENABLED=0 + the static-debian12
# distroless runtime mean no glibc dependency at runtime.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
        -trimpath \
        -ldflags "-s -w -X github.com/tmatens/container-sec-derive/internal/cli.version=${CSD_VERSION}" \
        -o /out/csd \
        ./cmd/csd

# Fetch the vendored ig binary for the target arch and verify it
# against the committed pin. The pin (ig-pin/SHA256SUMS) was signed
# by IG and verified at pin-bump time via scripts/refresh-ig-pin.sh
# (see ig-pin/README.md). At build time we re-verify offline with
# sha256sum -c — there is no fallback download path.
#
# Failure modes the chain catches:
#   - GitHub serves a different binary than the one IG signed: the
#     downloaded tarball's sha256 won't match the line in our pin file.
#   - Someone mutates ig-pin/SHA256SUMS in the repo: the binary IG
#     publishes won't match the tampered digest.
#   - Wrong IG_VERSION passed via --build-arg: the line referenced
#     by the grep below isn't present, the step exits non-zero.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY ig-pin/SHA256SUMS /pin/SHA256SUMS
RUN set -eu; \
    artifact="ig-linux-${TARGETARCH}-${IG_VERSION}.tar.gz"; \
    url="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/${artifact}"; \
    echo "Fetching ${url}"; \
    curl -fsSL "${url}" -o "/tmp/${artifact}"; \
    if [ -z "${TARGETARCH}" ]; then \
        echo "::error::TARGETARCH is empty — pass --build-arg TARGETARCH=<amd64|arm64> (CI does this from the matrix; the Makefile passes go env GOARCH)"; \
        exit 1; \
    fi; \
    expected_line="$(grep -E "  ${artifact}$" /pin/SHA256SUMS || true)"; \
    if [ -z "${expected_line}" ]; then \
        echo "::error::no digest for ${artifact} in ig-pin/SHA256SUMS — bump PinnedIGVersion and run scripts/refresh-ig-pin.sh"; \
        exit 1; \
    fi; \
    cd /tmp; \
    echo "${expected_line}" | sha256sum -c -; \
    tar -xzf "${artifact}"; \
    install -m 0755 /tmp/ig /out/ig; \
    /out/ig version

# --- runtime: distroless static, UID 0 with the labeled comment above ---
FROM gcr.io/distroless/static-debian12@sha256:a9fcaedd4c9b59e12dd65d954f0b5044f19b0647a8a3712e77205df9e7b102cd

ARG CSD_VERSION=dev
ARG IG_VERSION=v0.51.0

LABEL org.opencontainers.image.title="container-sec-derive" \
      org.opencontainers.image.description="Derive minimum container security config by observing a running container via eBPF (wraps Inspektor Gadget)." \
      org.opencontainers.image.url="https://github.com/tmatens/container-sec-derive" \
      org.opencontainers.image.source="https://github.com/tmatens/container-sec-derive" \
      org.opencontainers.image.documentation="https://github.com/tmatens/container-sec-derive#readme" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${CSD_VERSION}" \
      org.opencontainers.image.vendor="tmatens" \
      io.containersecderive.ig-version="${IG_VERSION}"

COPY --from=builder /out/csd /usr/local/bin/csd
COPY --from=builder /out/ig /usr/local/bin/ig

# Distroless static defaults to UID 0; restated for the same reason
# compose-lint's Dockerfile restates :nonroot — to make the choice
# survive a future base-image swap that defaults differently. See
# the file header for why nonroot is wrong here.
USER 0:0

ENTRYPOINT ["/usr/local/bin/csd"]
