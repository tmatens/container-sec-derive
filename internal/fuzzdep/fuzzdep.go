//go:build fuzzdep

// Package fuzzdep exists ONLY to retain the go-118-fuzz-build module in go.mod
// for the ClusterFuzzLite Go build (issue #174). `compile_native_go_fuzzer`
// rewrites each testing.F fuzz target to import
// github.com/AdamKorcz/go-118-fuzz-build/testing (its libFuzzer shim), so that
// module must be a required dependency — but nothing in csd imports it, so
// `go mod tidy` would otherwise drop it.
//
// The `fuzzdep` build tag is NEVER set in normal builds, tests, vet, or the
// release `go build`, so this import is never compiled into the `csd` binary —
// it stays stdlib-only (CLAUDE.md §Dependency pinning). `go mod tidy` retains the
// require because it considers build-tagged files across all configurations
// (the same mechanism as the standard tools.go pattern).
package fuzzdep

import _ "github.com/AdamKorcz/go-118-fuzz-build/testing"
