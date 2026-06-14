# Release checklist

How a `csd` release is cut. Tagging `vX.Y.Z` is the trigger for the whole
signed pipeline, so the steps before the tag are the ones that matter.

## What's automated vs. manual

**Automated** (`.github/workflows/release.yml`, on `push: tags: ['v*']`):

- Builds static `linux/amd64` + `linux/arm64` binaries, stamping
  `main.version` from the tag (`-X main.version=${tag#v}`), and verifies
  `csd --version` matches the tag.
- Generates SPDX + CycloneDX SBOMs and a sorted `SHA256SUMS`.
- cosign-signs each binary, the SBOMs, and the manifest (key-based,
  `--tlog-upload=false` — nothing hits the public Rekor log).
- Builds + pushes the multi-arch container image to
  `ghcr.io/tmatens/container-sec-derive` (**private**), signs the manifest,
  and attaches SBOM + OpenVEX attestations; verifies the published
  `--version` matches the tag.

**Manual:**

- Authoring the `CHANGELOG.md` entry and bumping the in-repo version strings
  (below).
- Creating and pushing the signed tag.
- Flipping GHCR package visibility to public — **COI-gated**, done out of band
  after the clearance decision (and only then is switching cosign back to
  keyless OIDC + Rekor a deliberate, reviewable change).

## Version strings to bump

`main.version` is stamped from the tag, but two in-repo strings are NOT and
must be bumped by hand in the release-prep PR:

- `ToolVersion` in `sidecar.go` → the new `X.Y.Z` (the sidecar `tool_version`).
- `SchemaVersion` in `sidecar.go` → bump the **minor** only if the sidecar JSON
  gained/changed fields this cycle (additive stays within `1.x`). If you bump
  it, regenerate the goldens (`go test ./... -run Golden -update-golden`) and
  update the `schema_version` assertions.
- `README.md`: the release badge, the GHCR image tags (`X.Y.Z` / `X.Y`), and
  the `docker pull` example.

## Steps

1. **Pre-flight.** On a clean `main`: `go vet ./...`, `go test ./...`,
   `go build`. Optionally `make smoke-wsl2` / `make smoke-fs` on a host with
   docker + the pinned `ig` (live BPF; CI also runs these per-PR).
2. **Update the changelog.** Rename `## [Unreleased]` to `## [X.Y.Z] - <today>`,
   add a fresh empty `## [Unreleased]` above it, and update the compare-link
   footer at the bottom of `CHANGELOG.md`.
3. **Bump the versions** above and refresh `README.md` / `ROADMAP.md` /
   `CLAUDE.md` status. Open a `Prepare X.Y.Z release` PR; let CI go green; merge.
4. **Tag the merge commit** (signed + annotated) and push:
   ```
   git checkout main && git pull --ff-only
   git tag -s vX.Y.Z -m "vX.Y.Z — <one-line summary>"
   git push origin vX.Y.Z
   ```
5. **Watch `release.yml`.** All jobs (build, SBOM, image publish, sign+publish,
   manifest+sign+attest) must go green. The GitHub Release is created with the
   signed artifacts.
6. **Post-release.** Confirm the GitHub Release lists the binaries, SBOMs,
   `SHA256SUMS`, and `.sig`/bundle files. GHCR visibility stays **private**
   until the COI decision; no in-pipeline approval gate exists for it.

## If something goes wrong

A failing release job does not roll back the tag. Fix forward: land the fix on
`main`, then either re-run the failed jobs (if the failure was transient) or cut
the next patch tag. The first signed release needed two such fixes (pin cosign
2.x; correct the image-SBOM upload flags) — both are now in `main`, so recent
releases run clean.

## Why this checklist exists

The tag is irreversible and outward-facing: it publishes signed artifacts and a
container image. Doing the changelog + version bumps in a reviewed PR *before*
the tag means the release commit is auditable and the tag points at a known-good,
CI-green `main`.
