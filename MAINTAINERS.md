# Maintainers

This file is the canonical list of people who hold merge and release rights on
`container-sec-derive`. Promotion and removal procedures are in
[GOVERNANCE.md](GOVERNANCE.md).

## Active maintainers

| Name        | GitHub                                 | Areas                                                    |
|-------------|----------------------------------------|----------------------------------------------------------|
| Todd Matens | [@tmatens](https://github.com/tmatens) | Repository admin, releases, security response, all areas |

## Emeritus maintainers

_None yet._

## Responsibilities

Per [GOVERNANCE.md](GOVERNANCE.md), every active maintainer:

- Reviews and merges pull requests; triages issues within 14 days.
- Responds to security reports within 7 days per
  [.github/SECURITY.md](.github/SECURITY.md).
- Cuts releases per [docs/RELEASING.md](docs/RELEASING.md).
- Holds the credentials needed to publish: GitHub admin (Releases), GHCR
  package admin, and the `COSIGN_PRIVATE_KEY` / `COSIGN_PASSWORD` repository
  secrets used for key-based signing (the committed `cosign.pub` is the public
  half). The bus factor is 1; see GOVERNANCE.md for the mitigation.
- Signs commits and tags (SSH). Note `csd` has **no** release-time
  tag-signature gate (`release.yml` fires on any `v*` push, no `verify-tag`
  job / `.github/allowed_signers`), so signing is a contributor-hygiene
  expectation enforced in review, not by CI.

## Adding or removing a maintainer

See [GOVERNANCE.md](GOVERNANCE.md) §"Adding a maintainer" and §"Removing a
maintainer". Updates to this file are made via PR like any other change.
