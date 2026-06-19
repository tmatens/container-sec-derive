#!/usr/bin/env bash
# Release-prep automation for csd (ROADMAP §Maturity; docs/RELEASING.md).
#
# Performs the deterministic, mechanical half of a release on a clean tree:
# rename the CHANGELOG [Unreleased] section, bump ToolVersion, refresh the
# README version strings, regenerate the sidecar goldens, and update the
# in-test version assertions — then build + vet + test as the gate. It does NOT
# tag, push, or touch SchemaVersion (schema bumps are deliberate, made by the
# feature PR that changed the schema, not by release-prep).
#
# Usage:  scripts/release-prep.sh X.Y.Z [YYYY-MM-DD]
#   (date defaults to today; the release workflow passes it explicitly)
#
# This is invoked by .github/workflows/release-prep.yml (workflow_dispatch) and
# is runnable locally (`make release-prep VERSION=X.Y.Z`) for inspection.
set -euo pipefail

NEW="${1:-}"
DATE="${2:-$(date +%Y-%m-%d)}"
SIDECAR="internal/sidecar/sidecar.go"
CHANGELOG="CHANGELOG.md"
README="README.md"
REPO_URL="https://github.com/tmatens/container-sec-derive"

if [[ ! "${NEW}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "release-prep: version must be X.Y.Z (got '${NEW}')" >&2
    exit 2
fi

# Current ToolVersion is the source of truth for the previous version.
OLD="$(awk -F'"' '/^[[:space:]]*ToolVersion[[:space:]]*=/ {print $2; exit}' "${SIDECAR}")"
if [[ -z "${OLD}" ]]; then
    echo "release-prep: could not read current ToolVersion from ${SIDECAR}" >&2
    exit 1
fi
if [[ "${OLD}" == "${NEW}" ]]; then
    echo "release-prep: ToolVersion is already ${NEW} — nothing to bump" >&2
    exit 2
fi
OLD_MINOR="${OLD%.*}"   # X.Y
NEW_MINOR="${NEW%.*}"
echo "release-prep: ${OLD} -> ${NEW} (${DATE})"

# 1. CHANGELOG: rename [Unreleased] -> [X.Y.Z], add a fresh [Unreleased], and
#    extend the compare-link footer. Fails loudly if the expected anchors are
#    missing (so a malformed CHANGELOG can't silently produce a bad release).
grep -qF '## [Unreleased]' "${CHANGELOG}" || { echo "release-prep: no '## [Unreleased]' in ${CHANGELOG}" >&2; exit 1; }
grep -qE "^\[Unreleased\]: .*compare/v${OLD}\.\.\.HEAD" "${CHANGELOG}" || { echo "release-prep: footer '[Unreleased]: ...compare/v${OLD}...HEAD' not found in ${CHANGELOG}" >&2; exit 1; }
# Section header: insert the new version section under [Unreleased].
perl -0pi -e "s/## \\[Unreleased\\]\\n/## [Unreleased]\\n\\n## [${NEW}] - ${DATE}\\n/" "${CHANGELOG}"
# Footer: repoint [Unreleased] to vNEW...HEAD and add the [NEW] compare line.
perl -0pi -e "s{\\[Unreleased\\]: \\Q${REPO_URL}\\E/compare/v${OLD}\\.\\.\\.HEAD}{[Unreleased]: ${REPO_URL}/compare/v${NEW}...HEAD\\n[${NEW}]: ${REPO_URL}/compare/v${OLD}...v${NEW}}" "${CHANGELOG}"

# 2. ToolVersion bump (SchemaVersion intentionally untouched).
sed -i "/ToolVersion/s/\"${OLD}\"/\"${NEW}\"/" "${SIDECAR}"

# 3. README version strings: the full X.Y.Z everywhere (badge, tag URL, status,
#    docker pull, ghcr examples) and the short `X.Y` image tag.
sed -i "s/${OLD}/${NEW}/g" "${README}"
sed -i "s/\`${OLD_MINOR}\`/\`${NEW_MINOR}\`/g" "${README}"

# 4. In-test version assertions that hardcode the old ToolVersion. Scoped to
#    *_test.go so prose/comments elsewhere are untouched; the build+test below
#    is the backstop if a stray literal is rewritten.
grep -rlF "\"${OLD}\"" --include='*_test.go' internal | while read -r f; do
    sed -i "s/\"${OLD}\"/\"${NEW}\"/g" "${f}"
done

# 5. Regenerate the sidecar goldens (they embed tool_version). Only the four
#    packages that define -update-golden; `go test ./...` rejects the flag
#    elsewhere.
go test ./internal/cli/ ./internal/observe/fs/ ./internal/observe/capadd/ ./internal/observe/egress/ -update-golden >/dev/null

# 6. Gate: the prepared tree must build, vet, and test clean.
gofmt -l internal/ cmd/ | grep . && { echo "release-prep: gofmt found unformatted files" >&2; exit 1; } || true
go vet ./...
go build -o /dev/null ./cmd/csd
go test ./... >/dev/null

echo "release-prep: prepared ${NEW}. Changed files:"
git --no-pager diff --stat
