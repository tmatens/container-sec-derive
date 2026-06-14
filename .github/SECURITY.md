# Security Policy

`container-sec-derive` (`csd`) runs **root-equivalent on the host**: live
observation needs `CAP_BPF` + `CAP_PERFMON`, `--pid=host`, and a
container-runtime socket. The full threat model and trust boundaries are in
[PLAN.md §Tool posture](../PLAN.md) and [docs/architecture.md](../docs/architecture.md).
Treat its blast radius like any other privileged BPF + container-API tool.

## Supported Versions

`csd` follows semantic versioning. Only the latest minor release receives
security fixes.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use GitHub's private vulnerability reporting:

1. Go to <https://github.com/tmatens/container-sec-derive/security/advisories/new>
2. Submit a report with reproduction steps and impact.

You should receive an acknowledgement within 7 days. If the report is valid, a
fix will be coordinated and released, and the advisory will be published with
credit unless you request otherwise.

## Scope

In scope:

- Code execution, privilege escalation, or information disclosure via crafted
  `ig`/`docker` output, fixtures (`--fixture` / `--mounts-fixture` /
  `--device-fixture`), or compose input to `--format compose-patch`.
- A derived profile that is **unsafe by construction** — e.g. one that drops a
  privilege the tool should have recommended keeping, in a way not already
  disclosed as a known limitation (see [docs/known-deltas.md](../docs/known-deltas.md)
  and the `--observe privileged` partial-decomposition caveat).
- Tampering with the published GitHub Release artifacts or the GHCR container
  image, or a break in their cosign signature / SBOM / OpenVEX attestation chain.
- Vulnerabilities in dependencies that are exploitable via `csd`.

Out of scope:

- A profile that is *incomplete* because the workload didn't exercise a code
  path during the observation window — this is the documented nature of
  BPF observation (see the standing `caveat` on every sidecar). File these as
  normal issues.
- Findings against the intentionally-permissive reference/synthetic workloads
  under `testdata/` (they exist to exercise the observers).
- The privileges `csd` itself requires to run — these are inherent to eBPF
  observation and documented in PLAN.md §Tool posture.

## Supply Chain

- Release binaries (`csd_linux_amd64`, `csd_linux_arm64`), the SBOMs
  (SPDX + CycloneDX), and `SHA256SUMS` are **cosign-signed key-based**
  (`--tlog-upload=false`, no public Rekor entry while the project is
  unpublished). Verify offline:
  `cosign verify-blob --key cosign.pub --insecure-ignore-tlog --signature <f>.sig <f>`.
- The container image (`ghcr.io/tmatens/container-sec-derive`) manifest is
  cosign-signed and carries SBOM + OpenVEX attestations, plus a dedicated
  `ig-provenance` attestation recording the vendored Inspektor Gadget pin.
- The vendored `ig` binary is cosign-verified **at pin time**
  (`scripts/refresh-ig-pin.sh`) and `sha256sum`-verified at build against the
  committed manifest — see [ig-pin/README.md](../ig-pin/README.md).
- Dependencies are kept current by Renovate. CodeQL and OpenSSF Scorecard
  coverage is tracked in [ROADMAP.md §Maturity](../ROADMAP.md).
