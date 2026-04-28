# `ig-pin/` — vendored Inspektor Gadget release pin

This directory pins the exact upstream Inspektor Gadget release that
csd's container image bundles. It exists so the image build can verify
the bundled `ig` binary fully offline at build time, without trusting
whatever is at `https://github.com/inspektor-gadget/inspektor-gadget/...`
on the day the build runs.

The pinned IG version itself lives in `main.go` as `PinnedIGVersion`
(it doubles as csd's runtime schema-compatibility check); this directory
pins the *artifact integrity* for that version.

## Files

- **`inspektor-gadget.pub`** — IG's long-lived cosign public key, vetted
  and committed at pin time. The Dockerfile uses this key (not whatever
  is at the upstream URL today) to verify the bundled `SHA256SUMS`.
- **`SHA256SUMS`** — IG's release manifest for the pinned version, listing
  sha256 digests for every artifact in the release.
- **`SHA256SUMS.bundle`** — IG's cosign signature bundle covering
  `SHA256SUMS`, sufficient for `cosign verify-blob --key ... --bundle ...`.

## Build-time verification flow (Dockerfile)

1. `cosign verify-blob --key ig-pin/inspektor-gadget.pub --bundle ig-pin/SHA256SUMS.bundle ig-pin/SHA256SUMS`
   — confirms the committed manifest was signed by IG.
2. Download `ig-linux-${TARGETARCH}-${PinnedIGVersion}.tar.gz` from the
   GitHub release.
3. `sha256sum -c <(grep "ig-linux-${TARGETARCH}-${PinnedIGVersion}.tar.gz$" ig-pin/SHA256SUMS)`
   — confirms the downloaded binary matches the manifest.
4. Extract; copy the `ig` binary into the final image.

A failure at any step is non-recoverable: the build aborts. There is no
fallback download path (PLAN.md §Supply-chain).

## Refresh procedure

When `PinnedIGVersion` in `main.go` is bumped, regenerate this directory
in the same commit by running:

```
./scripts/refresh-ig-pin.sh
```

The script fetches `inspektor-gadget.pub`, `SHA256SUMS`, and
`SHA256SUMS.bundle` for the version named in `main.go`, runs cosign
verification against the *fetched* key (not the previously committed
one — a key rotation is a deliberate event the pin bump records),
and overwrites the three files. Commit, sign, push.
