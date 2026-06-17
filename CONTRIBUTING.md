# Contributing to container-sec-derive

Thanks for wanting to help. This is a small, focused project that runs
**root-equivalent on the host** (eBPF + a container-runtime socket), so the bar
for contributions is correctness, conservative scope, and authoritative
grounding rather than breadth. Every new dependency, command surface, and
formatter lands under that blast radius.

## Before you start

- **Bug reports**: open an issue using the bug template.
- **Feature requests** (CLI flag, output format, config): use the feature template.
- **New observer proposals**: use the "New observer proposal" template. An
  observer must target a security setting that is genuinely *not derivable
  statically*, be backed by an Inspektor Gadget gadget available at the pinned
  IG release, and fit the roadmap. See [ROADMAP.md](ROADMAP.md).
- **Security vulnerabilities**: do *not* open a public issue. See
  [SECURITY.md](.github/SECURITY.md).
- **Larger changes**: open an issue to discuss first so you don't sink time into
  a change that doesn't fit the project's scope.

See [AGENTS.md](AGENTS.md) for the full design philosophy — the four-layer
architecture, the privilege posture, IG integration, and what's explicitly out
of scope (in [ROADMAP.md](ROADMAP.md)).

## Maintainers

- Todd Matens ([@tmatens](https://github.com/tmatens)) — repository admin,
  releases, security response.

Maintainers review and merge PRs, triage issues within 14 days, respond to
security reports within 7 days per [SECURITY.md](.github/SECURITY.md), and cut
releases per [docs/RELEASING.md](docs/RELEASING.md). See
[GOVERNANCE.md](GOVERNANCE.md) for how decisions get made.

## Development setup

```bash
git clone https://github.com/tmatens/container-sec-derive.git
cd container-sec-derive
go build -o csd .
```

Requires **Go 1.26+**. Live observation needs Inspektor Gadget (`ig`) at the
pinned release plus root — see [docs/dev-setup.md](docs/dev-setup.md). Most
development needs neither: the `--fixture` path replays pre-captured NDJSON, so
the whole pipeline runs without BPF/`ig`.

## Local quality checks

All must pass locally before you push. CI runs the same commands.

```bash
gofmt -l .          # Formatting — must print nothing
go vet ./...        # Vet
go test ./...       # Tests
go build -o csd .   # Build
```

Live-BPF behavior is exercised separately in CI (`integration.yml`:
`scripts/smoke_wsl2.sh`, `scripts/smoke_fs.sh`, `scripts/smoke_device.sh`) and
locally via `make smoke-wsl2` / `make smoke-fs` / `make smoke-device` (need
docker + the pinned `ig` + root). The kretprobe miss-rate harness
(`make missrate`) is `workflow_dispatch`-only to conserve CI minutes.

## Code standards

- **Go 1.26+.** Match the surrounding code's style and idiom.
- **The Go standard library is the only runtime dependency.** Any third-party
  runtime dep requires discussion first — this binary runs root-equivalent.
  Test-only and tooling deps are evaluated case by case.
- **Inspektor Gadget is a subprocess, never a library import.** Do not add
  `import` of any `inspektor-gadget` Go package (PLAN.md Decisions item 5).
- **No parser workarounds for IG schema drift.** Bump `PinnedIGVersion`, add a
  `testdata/ig-versions/<version>/` directory, regenerate fixtures, and re-run
  the reference smoke instead.
- **No AI authorship attribution** — no `Co-Authored-By` for AI, no "Generated
  by" notices, no "built with AI" badges, anywhere.

## Adding a new observer

Observers plug into the four-layer pipeline — **Observer → Attribution →
Aggregator → Formatter** — that v0.1 (caps), v0.2 (`fs`), and v0.3
(`devices`/`privileged`) all share. Don't collapse the layering to ship faster;
it is load-bearing. A new observer typically needs:

1. **An event model + classifier** — the IG event subset you consume and the
   predicate that selects the relevant events (cf. `fileevent.go`'s write-intent
   classifier, `deviceevent.go`'s `isDeviceOpen`).
2. **A decision/aggregation layer** — collapse raw events into the
   recommendation, reusing the shared attribution (`matchesRuntime`) and
   multi-replica correlation (cf. `fsdecision.go`, `devdecision.go`).
3. **An observe pipeline** — the live `ig run <gadget>` path plus a hermetic
   `--fixture` input (cf. `fsobserve.go`, `deviceobserve.go`).
4. **A `--observe <name>` selector** wired in `main.go`.
5. **An additive sidecar block** — new fields are `omitempty` so other
   observers' sidecars stay byte-identical; bump `SchemaVersion` within the
   current major (see [PLAN.md §Output schema](PLAN.md)).
6. **A confidence rubric** for the observer (cf. `computeFSConfidence`,
   `computeDeviceConfidence`) — reproducible from the recorded factors.
7. **All seven formatters** (`compose`, `json`, `docker-run`, `k8s`, `oci`,
   `compose-patch`, `compose-lint-profile`). `k8s`/`oci`/`compose-patch` are
   bespoke per output shape, not naive concatenation.
8. **The required test types** — a new observer must ship **all** of the
   per-observer test types in
   [docs/testing.md §Required test types per change](docs/testing.md): golden,
   a `run()`-level CLI table across every format, a confidence-rubric test, a
   live fake-`ig` test, multi-replica, negative/error-path, fuzz for any new
   parser, and `-race`. These are all hermetic (runnable without a kernel), so
   none may be deferred. Plus a deterministic synthetic-exerciser gate in the
   relevant smoke script (reference images may legitimately observe nothing
   post-attach; see [docs/known-deltas.md](docs/known-deltas.md)). Skipping a
   required type is a reviewable omission, not a gap to fix later.

### Observer requirements

- **Derives something static analysis cannot.** If a static linter
  (compose-lint) can already catch it, csd's job is at most emitting the
  satisfying profile, not re-implementing the check.
- **Honest about what it does NOT observe.** If the signal is partial (e.g. a
  gadget gap forces a subset), surface that to the user in the output, not just
  the docs — a partial result presented as complete is a correctness bug.
- **Conservative under uncertainty.** Never recommend dropping a privilege the
  observation can't prove is unused; never silently convert data writes to
  ephemeral storage.

## Commit conventions

- **One logical change per commit.** Don't bundle unrelated changes.
- **Imperative subject line, under 72 characters.** "Add devices observer", not
  "Added devices observer" or "devices observer".
- **Explain the *why* in the body**, not just the *what* — the diff shows what
  changed.
- **Sign your commits** (SSH) so GitHub shows "Verified". See
  [commit signing](#commit-signing).
- **Sign off your commits** with `git commit -s` to add the `Signed-off-by:`
  [DCO](#developer-certificate-of-origin) trailer — this is separate from
  cryptographic signing.
- **No AI attribution** (see Code standards).

We do *not* use [Conventional Commits](https://www.conventionalcommits.org/)
prefixes (`feat:`, `fix:`). Descriptive imperative subjects read naturally in
`git log` without tooling.

### Commit signing

All commits to `main` must be signed. SSH signing reuses the key you already
push with:

```bash
git config gpg.format ssh
git config user.signingkey "key::$(cat ~/.ssh/id_ed25519.pub)"
git config commit.gpgsign true
```

Add the *same* public key to GitHub as a **Signing Key** (separate from
authentication keys) at <https://github.com/settings/ssh/new>. Verify locally
with `git log --format='%h %G? %s'` — every commit should show `G` once your
local `gpg.ssh.allowedSignersFile` is configured. (This repo has **no**
release-time tag-signature gate, so signing is enforced in review, not by CI.)

### Developer Certificate of Origin

All commits must carry a `Signed-off-by:` trailer certifying you wrote the
change (or may submit it under this project's MIT license) — the
[Developer Certificate of Origin](https://developercertificate.org). It is
independent of commit signing: signing proves *who committed*, DCO asserts
*right to contribute*.

```bash
git commit -s -m "Your change"
```

The `Signed-off-by` name and email must match your commit author identity. Fix
existing commits with `git commit --amend --signoff` or `git rebase --signoff main`.

## Pull requests

All changes to `main` go through a PR — including maintainer changes.

1. **Create a branch** from `main`, named descriptively:
   `feat/v0.4-socket-observer`, `fix/device-default-set`, `docs/contributing`.
2. **Make small, focused commits** (see [commit conventions](#commit-conventions)).
3. **Run local checks** — all four must pass before you push.
4. **Open a PR** and fill out the template. Link any related issue.
5. **Wait for CI** — all required checks must be green before merge.
6. **Respond to review.** All comments resolved before merge.
7. **Squash-merge** when approved, so `main` stays linear with one commit per
   logical change.

### PR expectations

- **Keep PRs small.** Easier to review, revert, and bisect.
- **Don't mix refactors with behavior changes.** Land the refactor first.
- **Update tests.** New observers must ship every required test type in
  [docs/testing.md §Required test types per change](docs/testing.md) (golden,
  `run()`-level CLI table, confidence rubric, live fake-`ig`, multi-replica,
  negative/error-path, fuzz for new parsers, `-race`) plus a smoke gate; a
  bug fix needs a regression test that fails before the fix.
- **Update the docs your change touches in the same PR** so the entry-point docs
  never trail `main`: keep the CLAUDE.md/README status current, update the
  PLAN.md build order, tick PLAN.md success-criteria boxes *only with evidence*,
  and bump ROADMAP if a phase moved. Don't reference uncommitted files from
  committed prose.
- **Add a `CHANGELOG.md` `[Unreleased]` entry** for any version-visible change
  (new observer/formatter/flag, behavior change, schema bump, security fix),
  grouped per [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Pure
  refactors, test-only, and internal-doc PRs don't need one.

## Reporting bugs

Use the bug report issue template. Include:

- The minimal reproducer — a fixture NDJSON (`--fixture`) and the exact `csd`
  invocation, ideally something that reproduces without live `ig`.
- What you expected vs. what actually happened (full command output).
- Your `csd` version (`csd --version`), Go version (`go version`), and — for
  live-observation bugs — kernel and `ig` versions.

## Code of conduct

This project follows the [Contributor Covenant](.github/CODE_OF_CONDUCT.md). By
participating you agree to uphold it.
