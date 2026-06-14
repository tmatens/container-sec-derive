<!--
Thanks for contributing! Fill in the sections below; delete any that don't
apply. csd runs root-equivalent (CAP_BPF + CAP_PERFMON + --pid=host + a
container-runtime socket), so every new dependency, command surface, and
formatter lands under that blast radius — keep changes small and reviewable.
-->

## Summary

<!-- What does this PR change? One or two sentences. -->

## Why

<!-- Why is this change needed? Link the issue, the PLAN/ROADMAP section, or the
     observed behavior that motivated it. -->

Closes #

## Type of change

- [ ] New observer (e.g. `--observe <name>`)
- [ ] New formatter
- [ ] Bug fix
- [ ] Refactor (no behavior change)
- [ ] Documentation
- [ ] Build / CI / release tooling
- [ ] Other:

## Checklist

- [ ] Commits are SSH-signed (GitHub shows **Verified**) and carry the DCO `Signed-off-by` trailer
- [ ] One logical change per commit; no unrelated changes bundled in
- [ ] `go vet ./...`, `go test ./...`, and `go build` pass locally
- [ ] New/changed behavior has tests (positive **and** negative cases)
- [ ] No new runtime dependency outside the Go stdlib (or it's called out and justified above)
- [ ] Docs updated where behavior changed: `README.md`, `PLAN.md`/`ROADMAP.md`, the CLAUDE.md status section, and a `CHANGELOG.md` `[Unreleased]` entry for any version-visible change
- [ ] No AI authorship attribution anywhere (commits, comments, docs)

## New observer only

<!-- Delete this section if this PR is not a new observer. -->

- [ ] Plugs into the four-layer pipeline (Observer → Attribution → Aggregator → Formatter) without collapsing the layering
- [ ] Signal source is a pinned `ig` gadget (no `ig` Go-library import; no parser workaround for schema drift)
- [ ] Confidence rubric defined in `PLAN.md` and referenced, not restated
- [ ] Reference ground truth + an integration-CI smoke gate added
- [ ] `docs/known-deltas.md` updated with any observed-vs-truth deltas (cause + disposition)

## Breaking changes

<!-- Does this change the CLI, the sidecar schema (schema_version), exit codes,
     or the compose-lint contribution contract? If yes, describe the migration
     path and bump schema_version. If no, write "None". -->

None
