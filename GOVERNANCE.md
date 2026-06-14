# Governance

`container-sec-derive` is intentionally small and single-maintainer. This
document describes how decisions get made and who is accountable for what — so
a new contributor can predict how their PR will be evaluated, and a future
successor can pick up the project without rediscovering the conventions from
`git log`.

## Roles

There is one role: **maintainer.** The current maintainer is listed in
[MAINTAINERS.md](MAINTAINERS.md). The maintainer:

- Reviews and merges pull requests.
- Triages issues within 14 days (per [CONTRIBUTING.md](CONTRIBUTING.md)).
- Responds to security reports within 7 days (per [.github/SECURITY.md](.github/SECURITY.md)).
- Cuts releases per [docs/RELEASING.md](docs/RELEASING.md).
- Holds the credentials needed to publish (GitHub Releases, the GHCR package,
  the cosign signing key) — see [MAINTAINERS.md](MAINTAINERS.md).

There is no separate "committer," "reviewer," or "TSC" role. The bus factor is
1; we are honest about that.

Every code change — including changes by the maintainer — goes through a pull
request. There are no direct pushes to `main`, including from the maintainer's
account. Branch protection enforces this.

## Decision-making

Decisions are made by **lazy consensus**: a proposal goes up as an issue or PR;
if no maintainer-level objection is raised within a reasonable window, it lands.
Reasonable means roughly:

- **PRs against an existing observer, formatter, doc, or fix** — merge-ready
  when CI passes and a maintainer has reviewed. No waiting period.
- **A new observer** — discussion in the linked issue first (use the
  "New observer proposal" template). The bar is a roadmap-aligned signal that
  is genuinely *not derivable statically*, an Inspektor Gadget gadget available
  at the pinned release that exposes it, and a plan to honor the four-layer
  contract (Observer → Attribution → Aggregator → Formatter) with ground-truth
  tests. See [ROADMAP.md](ROADMAP.md) and [PLAN.md](PLAN.md).
- **A new runtime dependency, a new CLI flag, a sidecar schema change, a new
  IG pin, or anything that would force a MAJOR bump** — open an issue first.
  The maintainer's call. `csd` runs root-equivalent, so the bar for new
  dependencies and command surface is high (stdlib-first; see
  [AGENTS.md](AGENTS.md)).

The maintainer may exercise a veto on any change that conflicts with the
project's stated scope (see "Out of scope" in [ROADMAP.md](ROADMAP.md) and the
overview in [README.md](README.md)). Vetoes are explained in writing on the PR
or issue thread.

## Escalation

If you disagree with a decision the maintainer made:

1. Reopen the discussion on the original issue or PR with the additional
   context or evidence you have.
2. If the disagreement persists, open a new issue tagged `governance:appeal`
   summarizing both positions.
3. Because there is currently no second maintainer to break a tie, the final
   call rests with the listed maintainer. The MIT license is the structural
   escape hatch: anyone is free to fork.

When a second maintainer is added (see "Adding a maintainer" below), this
escalation path will become a vote.

## Adding a maintainer

The project would benefit from raising the bus factor to >=2. A contributor
becomes a candidate after demonstrating sustained high-quality contributions —
typically:

- Multiple merged PRs across observers, the aggregation/formatter layers, and
  CI/release.
- Reviewed at least one new-observer PR end to end.
- Familiar with [docs/RELEASING.md](docs/RELEASING.md) and the supply-chain
  conventions in [AGENTS.md](AGENTS.md) (cosign signing, the `ig` pin,
  SHA-pinned actions).
- Willing to share the on-call load for security reports (7-day SLA) and the
  release ceremony.

Promotion is a maintainer decision documented in a PR that updates
[MAINTAINERS.md](MAINTAINERS.md). The new maintainer is granted GitHub admin on
the repo, GHCR package admin, and access to the cosign signing secrets.

## Removing a maintainer

A maintainer who steps down opens a PR removing themselves from
[MAINTAINERS.md](MAINTAINERS.md). A maintainer who becomes non-responsive for
>90 days may be removed by another maintainer in a PR that documents the
attempted contacts.

## Code of conduct

All participants agree to the [Contributor Covenant 2.1](.github/CODE_OF_CONDUCT.md).
Enforcement actions (warnings, removal of contributions, bans) are the
maintainer's call; the same lazy-consensus and escalation paths apply.

## Changes to this document

Governance changes go through a PR like any other change. Substantive changes —
adding/removing roles, changing the decision rule, changing the appeal path —
should be tagged `governance` and held open for at least 7 days to give other
contributors time to comment.
