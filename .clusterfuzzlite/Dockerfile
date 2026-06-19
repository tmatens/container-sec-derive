# ClusterFuzzLite build image (ROADMAP §Maturity). The OSS-Fuzz base-builder-go
# image provides compile_native_go_fuzzer + the Go fuzzing toolchain.
#
# DIGEST PIN: this should be digest-pinned (CLAUDE.md §Dependency pinning). It is
# left on the :v1 tag here only because the digest could not be resolved from the
# dev sandbox (gcr.io is not in the egress allowlist). Renovate manages this pin —
# its first run will convert :v1 to a sha256 digest; confirm that lands.
FROM gcr.io/oss-fuzz-base/base-builder-go:v1

COPY . $SRC/container-sec-derive
WORKDIR $SRC/container-sec-derive
COPY .clusterfuzzlite/build.sh $SRC/build.sh
