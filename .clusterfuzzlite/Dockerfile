# ClusterFuzzLite build image (ROADMAP §Maturity). The OSS-Fuzz base-builder-go
# image provides compile_native_go_fuzzer + the Go fuzzing toolchain (it
# auto-downloads the go.mod toolchain, so csd's Go 1.26 is fine). Digest-pinned
# per CLAUDE.md §Dependency pinning; Renovate manages the bump (the :v1 tag in the
# comment tracks which base-builder-go line it maps to).
FROM gcr.io/oss-fuzz-base/base-builder-go:v1@sha256:23af99109dcb1c4da582f485b12d24a5c678f9aa5e7397989086c8481032127f

COPY . $SRC/container-sec-derive
WORKDIR $SRC/container-sec-derive
COPY .clusterfuzzlite/build.sh $SRC/build.sh
