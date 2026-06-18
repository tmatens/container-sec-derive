# AGENTS.md

`container-sec-derive` (`csd`) is largely agent-developed. This file is the
durable design philosophy and contribution contract for any contributor —
human or agent. It deliberately omits the current release status (which drifts);
for that, see `README.md` and `CHANGELOG.md`. For the full architecture,
decisions, threat model, and success criteria, read **[PLAN.md](PLAN.md)**; for
the observer roadmap and what's out of scope, **[ROADMAP.md](ROADMAP.md)**; for
the mechanical contribution rules, **[CONTRIBUTING.md](CONTRIBUTING.md)**.

## Project overview

A runtime tool that derives the minimum container security configuration an
image actually needs by observing a running container via eBPF (it wraps
Inspektor Gadget). Go 1.26+, MIT, a one-shot CLI. It is the *dynamic* companion
to the static linter [compose-lint](https://github.com/tmatens/compose-lint):
where compose-lint catches insecure config statically, `csd` observes a running
container and emits the satisfying profile (which can be contributed back to the
compose-lint catalog).

## Architecture — the four-layer pipeline

Every observer plugs into the same four layers:

**Observer → Attribution → Aggregator → Formatter.**

- **Observer** — runs an `ig` gadget (subprocess) or replays a fixture; yields
  typed events.
- **Attribution** — maps events to the target container(s); shared across
  observers (`matchesRuntime`), including multi-replica selection.
- **Aggregator** — collapses raw events into a recommendation with auditable
  evidence (event counts, comm samples, offsets).
- **Formatter** — renders the recommendation in one of seven output shapes.

Do **not** collapse the layering to ship a second observer faster — it is
load-bearing. Observers added so far: caps (`cap_capable`), `fs` (`trace_open`
write-intent), `devices` + `privileged` (`trace_open` on `/dev` + caps),
`capadd` (`cap_capable` reuse), `egress` (`trace_tcp`). See PLAN.md
§Architecture.

The layering is **enforced by package boundaries**, not just convention: a
`cmd/csd` shim over `internal/cli`, foundation leaves (`internal/{exit,sidecar,
ig,attrib}`), one `internal/observe/<name>` package per observer, and
`internal/format`. The import direction only points "down," so the compiler
rejects an observer that calls sideways. **[docs/organization.md](docs/organization.md)
is the code-organization standard** — the package map, the import rules, where
formatters live, and the "new observer = new `internal/observe/<name>` package"
rule. Read it before adding or moving code.

## Output schema

The JSON evidence sidecar is the canonical artifact; all formatters derive from
it. The schema is `schema_version`'d (semver-on-schema): each observer adds its
own top-level block, all `omitempty`, so a run that didn't use an observer
serializes without its block (additive within a major; consumers reject unknown
majors). The full field-by-field contract lives in PLAN.md §Output schema —
don't restate it elsewhere.

## Confidence rubric

`csd`'s analog of severity: `high` / `moderate` / `low`, mechanically derived
and reproducible from the recorded `factors`. Each observer has its own rubric
(device opens are sparse, so the device rubric has no event-count floor). The
rubric definitions live in PLAN.md §Confidence scoring — update there, reference
elsewhere.

## Privilege posture

`csd` runs with `CAP_BPF` + `CAP_PERFMON` + `--pid=host` + a container-runtime
socket — **root-equivalent on the host.** Every new dependency, command
surface, and formatter lands under that blast radius, which is why the
dependency bar is high and the runtime is stdlib-only. PLAN.md §Tool posture has
the threat model; [.github/SECURITY.md](.github/SECURITY.md) has the disclosure
policy.

## IG integration

Subprocess, **not** a library import (Decisions item 5). The IG schema is pinned
per release (`PinnedIGVersion` / `MIN_IG_VERSION` / `MAX_TESTED_IG_VERSION` plus
per-version fixtures under `testdata/ig-versions/<version>/`). Bumping the pin =
add a version directory, regenerate sample NDJSON, re-run reference smoke,
commit. Never patch the parser to cope with schema drift across pinned versions.

## Contribution rules (summary — CONTRIBUTING.md is authoritative)

- One logical change per commit; imperative subject ≤72 chars; no Conventional
  Commits prefixes.
- All commits SSH-signed and DCO signed-off (`git commit -s`).
- All changes via PR, squash-merge to `main`; update the docs your change
  touches in the same PR; add a `CHANGELOG.md` `[Unreleased]` entry for any
  version-visible change.
- A new observer must ship **every** required test type in
  [docs/testing.md §Required test types per change](docs/testing.md) (golden,
  `run()`-level CLI table, confidence rubric, live fake-`ig`, multi-replica,
  negative/error-path, fuzz for new parsers, `-race`); a bug fix ships a
  regression test that fails before the fix. Skipping a required type is a
  reviewable omission, not a deferral — they are all hermetic.
- SHA-pin every GitHub Actions `uses:` (only exception `uses: ./`); digest-pin
  Docker base images; the vendored `ig` is cosign-verified at pin time.

## Things to avoid

- No AI authorship attribution (no `Co-Authored-By` for AI, no "Generated by"
  notices, no "built with AI" badges).
- No runtime dependencies beyond the Go stdlib without discussion.
- No direct `ig` Go library imports — subprocess only.
- No parser workarounds for IG schema drift; bump the pin and regenerate
  fixtures instead.
- No mutable refs in CI.
- No enforcement: `csd` observes and recommends; it does not apply config.
- No static image/Compose/Dockerfile analysis — that is compose-lint's / other
  tools' job (see ROADMAP.md §Out of scope).
- A partial result presented as complete is a correctness bug — surface gaps in
  the output, not only the docs.
