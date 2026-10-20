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

**Automated by `release-prep.yml` (workflow_dispatch, target version) — the
deterministic pre-tag bumps:** renames the `CHANGELOG.md` `[Unreleased]` section
to `[X.Y.Z]` + extends the compare-link footer, bumps `ToolVersion`, refreshes
the `README.md` version strings, regenerates the sidecar goldens, and updates the
in-test version assertions — then `go vet`/`build`/`test` as the gate and opens a
`Prepare X.Y.Z release` PR. Runs `scripts/release-prep.sh`; the same script is
available locally as `make release-prep VERSION=X.Y.Z` (mutate + gate only — no
commit/push/tag). It does **not** touch `SchemaVersion` (see below).

**Manual:**

- Authoring the `CHANGELOG.md` *content* under `[Unreleased]` as features land
  (release-prep only renames the section, it doesn't write the entries) and any
  prose status in `CLAUDE.md` / `ROADMAP.md`.
- `SchemaVersion` — bumped by the feature PR that changes the schema, not at
  release.
- Reviewing + merging the prepare-release PR.
- Creating and pushing the signed tag.
- Flipping GHCR package visibility to public — a manual step, done out of band
  after the clearance decision (and only then is switching cosign back to
  keyless OIDC + Rekor a deliberate, reviewable change).

## Version strings

`main.version` is stamped from the tag. The other in-repo version strings are
handled by `scripts/release-prep.sh` (run via the workflow / `make release-prep`):

- `ToolVersion` in `sidecar.go` (the sidecar `tool_version`) → bumped to `X.Y.Z`.
- `README.md`: the release badge, the GHCR image tags (`X.Y.Z` / `X.Y`), and the
  `docker pull` example → rewritten from the previous version.
- The sidecar goldens (`testdata/*_golden.json`) and the in-test `tool_version`
  assertions → regenerated / bumped.

**`SchemaVersion` is the deliberate exception** — release-prep does **not** touch
it. Bump it (minor, additive within `1.x`) in the *feature PR* that changes the
sidecar JSON, regenerate the goldens, and update the `schema_version` assertions
there. By release time it is already correct.

## Steps

1. **Pre-flight.** On a clean `main`: `go vet ./...`, `go test ./...`,
   `go build`. Optionally `make smoke-wsl2` / `make smoke-fs` on a host with
   docker + the pinned `ig` (live BPF; CI also runs these per-PR). Make sure the
   `CHANGELOG.md` `[Unreleased]` section has the entries for this release and any
   prose status in `CLAUDE.md` / `ROADMAP.md` is current (release-prep does the
   version mechanics, not the narrative).
2. **Run release-prep.** Dispatch `release-prep.yml` with the target `X.Y.Z`
   (or, to inspect locally first, `make release-prep VERSION=X.Y.Z`). It renames
   the changelog section, bumps `ToolVersion`, refreshes the README version
   strings, regenerates the goldens, updates the in-test version assertions,
   gates on build/vet/test, and opens the `Prepare X.Y.Z release` PR. Review the
   diff and merge. (The PR is GITHUB_TOKEN-opened so the `pull_request` suite
   doesn't auto-run; the prep job's build/test is the gate — push an empty commit
   if you want the full suite too.)
3. **Tag the merge commit** (signed + annotated) and push:
   ```
   git checkout main && git pull --ff-only
   git tag -s vX.Y.Z -m "vX.Y.Z — <one-line summary>"
   git push origin vX.Y.Z
   ```
4. **Watch `release.yml`.** All jobs (build, SBOM, image publish, sign+publish,
   manifest+sign+attest) must go green. The GitHub Release is created with the
   signed artifacts.
5. **Post-release.** Confirm the GitHub Release lists the binaries, SBOMs,
   `SHA256SUMS`, and `.sig`/bundle files. GHCR visibility stays **private**
   until the maintainer decides to; no in-pipeline approval gate exists for it.

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
