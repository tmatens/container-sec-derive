#!/usr/bin/env bash
# refresh-ig-pin.sh — refresh ig-pin/ artifacts to match the version
# currently named in internal/ig/ig.go (PinnedIGVersion).
#
# Run this when bumping PinnedIGVersion. The script fetches IG's
# public key, SHA256SUMS, and SHA256SUMS.bundle for the new version,
# verifies the manifest with cosign, and overwrites the committed
# files in ig-pin/. The output is intended to be reviewed and
# committed in the same change as the main.go bump.
#
# Per CLAUDE.md §IG integration, bumping the pin also requires:
#   - new testdata/ig-versions/<version>/ directory
#   - regenerated sample.ndjson against the live ig
#   - a reference-image smoke pass
# This script handles only the binary-vendoring half.

set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(awk -F'"' '/^[[:space:]]+PinnedIGVersion[[:space:]]+=/ {print $2; exit}' internal/ig/ig.go)"
if [[ -z "${VERSION}" ]]; then
    echo "::error::could not extract PinnedIGVersion from internal/ig/ig.go" >&2
    exit 1
fi
echo "Refreshing ig-pin/ for ${VERSION}"

if ! command -v cosign >/dev/null 2>&1; then
    echo "::error::cosign is not on PATH; install from https://github.com/sigstore/cosign" >&2
    exit 1
fi

base="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${VERSION}"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

for f in inspektor-gadget.pub SHA256SUMS SHA256SUMS.bundle; do
    echo "  fetch ${f}"
    curl -fsSL "${base}/${f}" -o "${tmp}/${f}"
done

# Cosign verifies SHA256SUMS using the *freshly fetched* public key. A
# key rotation upstream is a deliberate event captured by the diff
# this script produces; a maintainer reviewing the pin bump should
# notice the .pub file changing.
echo "  cosign verify-blob"
cosign verify-blob \
    --key "${tmp}/inspektor-gadget.pub" \
    --bundle "${tmp}/SHA256SUMS.bundle" \
    "${tmp}/SHA256SUMS"

# Sanity-check the manifest covers both arches we ship images for.
for arch in amd64 arm64; do
    if ! grep -qE "^[0-9a-f]{64}  ig-linux-${arch}-${VERSION}\.tar\.gz$" "${tmp}/SHA256SUMS"; then
        echo "::error::SHA256SUMS does not list ig-linux-${arch}-${VERSION}.tar.gz" >&2
        exit 1
    fi
done

mkdir -p ig-pin
mv "${tmp}/inspektor-gadget.pub" ig-pin/inspektor-gadget.pub
mv "${tmp}/SHA256SUMS" ig-pin/SHA256SUMS
mv "${tmp}/SHA256SUMS.bundle" ig-pin/SHA256SUMS.bundle

echo "ig-pin/ updated for ${VERSION}. Review the diff and commit."
