#!/usr/bin/env bash
#
# Emit the vendored-`ig` provenance predicate (the body of an in-toto custom
# predicate) to stdout, sourced deterministically from the committed pin —
# no network, no jq. Consumed by .github/workflows/release.yml's
# "Attest ig provenance to image" step:
#
#   ./scripts/gen-ig-provenance.sh > ig-provenance.json
#   cosign attest --type <IG_PROVENANCE_TYPE> --predicate ig-provenance.json <image@digest>
#
# where IG_PROVENANCE_TYPE is
#   https://github.com/tmatens/container-sec-derive/attestations/ig-provenance/v1
#
# The data is exactly what already gates the build: the IG version
# (main.go PinnedIGVersion), the upstream per-arch tarball digests
# (ig-pin/SHA256SUMS — itself cosign-signed by IG, see ig-pin/README.md),
# and the fingerprint of IG's public key. Values are hex digests / a vX.Y.Z
# version string, so the heredoc emits valid JSON without escaping.
set -euo pipefail
cd "$(dirname "$0")/.."

version="$(awk -F'"' '/^[[:space:]]+PinnedIGVersion[[:space:]]+=/ {print $2; exit}' main.go)"
[ -n "$version" ] || { echo "gen-ig-provenance: could not read PinnedIGVersion from main.go" >&2; exit 1; }

pin="ig-pin/SHA256SUMS"
[ -f "$pin" ] || { echo "gen-ig-provenance: $pin not found" >&2; exit 1; }

# digest <arch> -> sha256 of ig-linux-<arch>-<version>.tar.gz from the pin
digest() {
	local f="ig-linux-$1-${version}.tar.gz" d
	d="$(awk -v f="$f" '$2==f {print $1; exit}' "$pin")"
	[ -n "$d" ] || { echo "gen-ig-provenance: no digest for $f in $pin (bump PinnedIGVersion and run scripts/refresh-ig-pin.sh?)" >&2; exit 1; }
	printf '%s' "$d"
}
amd64="$(digest amd64)"
arm64="$(digest arm64)"
keyfp="$(sha256sum ig-pin/inspektor-gadget.pub | awk '{print $1}')"

cat <<EOF
{
  "component": "inspektor-gadget",
  "role": "vendored runtime dependency: the ig binary csd subprocesses for eBPF capability observation",
  "version": "${version}",
  "source": "https://github.com/inspektor-gadget/inspektor-gadget/releases/tag/${version}",
  "artifacts": [
    { "name": "ig-linux-amd64-${version}.tar.gz", "sha256": "${amd64}" },
    { "name": "ig-linux-arm64-${version}.tar.gz", "sha256": "${arm64}" }
  ],
  "verification": {
    "cosignVerified": true,
    "signedManifest": "ig-pin/SHA256SUMS",
    "publicKey": "ig-pin/inspektor-gadget.pub",
    "publicKeySha256": "${keyfp}",
    "method": "IG's cosign-signed release manifest is verified against IG's key at pin-bump time (scripts/refresh-ig-pin.sh) and the tarball is re-checked offline by sha256 against this pin at image build (Dockerfile). No fallback download path."
  }
}
EOF
