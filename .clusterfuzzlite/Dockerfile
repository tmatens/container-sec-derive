# ClusterFuzzLite build image (ROADMAP §Maturity). The OSS-Fuzz base-builder-go
# image provides compile_native_go_fuzzer + the Go fuzzing toolchain (it
# auto-downloads the go.mod toolchain, so csd's Go 1.26 is fine). Digest-pinned
# per CLAUDE.md §Dependency pinning; Renovate manages the bump (the :v1 tag in the
# comment tracks which base-builder-go line it maps to).
FROM gcr.io/oss-fuzz-base/base-builder-go:v1@sha256:32f16d89a4849cb0747ffffb9d4e371e48a10c52165905ecd1c8333f09a612f6

COPY . $SRC/container-sec-derive
WORKDIR $SRC/container-sec-derive
COPY .clusterfuzzlite/build.sh $SRC/build.sh
