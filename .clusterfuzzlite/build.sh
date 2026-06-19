#!/usr/bin/env bash
# ClusterFuzzLite build script, run inside the OSS-Fuzz base-builder-go image.
# Compiles csd's Go native fuzz targets (testing.F, in *_test.go) into libFuzzer
# binaries via compile_native_go_fuzzer (provided by the base image).
#
# Each target hardens a parser/aggregator that consumes semi-untrusted input
# (ig NDJSON, docker inspect JSON, compose files) — and csd runs root-equivalent,
# so parser robustness matters. Targets are validated locally with
# `go test -fuzz=<name> -fuzztime=Ns ./<pkg>/`.
set -euo pipefail

cd "$SRC/container-sec-derive"

# compile_native_go_fuzzer <import-path> <FuzzFunc> <output-binary-name>
compile_native_go_fuzzer github.com/tmatens/container-sec-derive/internal/observe/capadd FuzzAggregateCapadd      FuzzAggregateCapadd
compile_native_go_fuzzer github.com/tmatens/container-sec-derive/internal/observe/fs     FuzzFileEventUnmarshal    FuzzFileEventUnmarshal
compile_native_go_fuzzer github.com/tmatens/container-sec-derive/internal/observe/fs     FuzzParseMountDestinations FuzzParseMountDestinations
compile_native_go_fuzzer github.com/tmatens/container-sec-derive/internal/format         FuzzCapEventUnmarshal     FuzzCapEventUnmarshal
compile_native_go_fuzzer github.com/tmatens/container-sec-derive/internal/format         FuzzCapaddComposePatch    FuzzCapaddComposePatch
compile_native_go_fuzzer github.com/tmatens/container-sec-derive/internal/observe/egress FuzzAggregateEgress       FuzzAggregateEgress
