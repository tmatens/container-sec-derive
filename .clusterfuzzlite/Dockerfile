# ClusterFuzzLite build image (ROADMAP §Maturity). The OSS-Fuzz base-builder-go
# image provides compile_native_go_fuzzer + the Go fuzzing toolchain (it
# auto-downloads the go.mod toolchain, so csd's Go 1.26 is fine). Digest-pinned
# per CLAUDE.md §Dependency pinning; Renovate manages the bump (the :v1 tag in the
# comment tracks which base-builder-go line it maps to).
FROM gcr.io/oss-fuzz-base/base-builder-go:v1@sha256:031e528038848b75c7c4339bd542ad6c41587ee0e40a5f24f829719f9b93f34b

COPY . $SRC/container-sec-derive
WORKDIR $SRC/container-sec-derive
COPY .clusterfuzzlite/build.sh $SRC/build.sh
