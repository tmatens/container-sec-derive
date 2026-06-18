# Code organization

This is the **code-organization standard** for `container-sec-derive`. It is to
the package layout what [docs/testing.md](testing.md) is to the test suite: the
one place that says where new code goes and which direction dependencies may
point. A change that lands in the wrong package — most visibly, a new observer
that arrives as a pile of files in the repo root — is a reviewable omission, not
a style nit.

It exists because the documented four-layer architecture
(**Observer → Attribution → Aggregator → Formatter**, see PLAN.md §Architecture)
is only as real as the package boundaries that enforce it. Flat-package Go lets
any file call any other, so the layering can erode silently. Real package
boundaries make the import direction load-bearing: the compiler rejects an
import that points the wrong way.

The flat `package main` is gone (issue #149): there is **no `.go` source in the
repo root**. The binary builds from `./cmd/csd`, and the layout below is the
real, landed structure — not an aspiration. New code is written against it, and
CI enforces the import direction via the package boundaries.

## Package map

```
cmd/csd/main.go            thin entry point: var version, parse args → cli.Run() → os.Exit(code)
internal/
  exit/                    EX_* exit-code contract + the typed coded/ambiguous errors
  sidecar/                 the canonical JSON evidence schema: Sidecar + every evidence
                           and recommendation type, NewSidecar, trace_health, Confidence
  ig/                      signal-acquisition seam: IG version pin, gadget OCI refs,
                           `ig version` schema gate, ig-stderr drop-counter parsing
  attrib/                  attribution layer: Opts (target selection) + MatchesRuntime,
                           ambiguity guard — observer-agnostic, knows no event type
  exit, sidecar, ig, attrib are the FOUNDATION (leaves): stdlib-only deps plus,
  at most, each other in the one-way order exit/sidecar ← ig/attrib.
  observe/                   shared observer scaffolding: SortedKeys, the WSL2 +
                             advisory-warning notes, the cross-observer
                             confidence helpers (worse-of-two for privileged)
  observe/
    caps/                  cap event + aggregate + decide + confidence (trace_capabilities)
    fs/                    fileevent, fsobserve, fsdecision, fsconfidence (trace_open write-intent)
    devices/               deviceevent, deviceobserve, devdecision, deviceconfidence (trace_open /dev)
    privileged/            privilegedobserve (caps + devices composition; its formatter
                           is in internal/format — it reuses the compose machinery)
    capadd/                capadd, capaddobserve, capadddecision, capaddconfidence (trace_capabilities)
    egress/                egressevent, egress, egressobserve, egressdecision, egressconfidence,
                           egressformat (trace_tcp) — owns its enforcement formatter (see Formatters)
  format/                  the compose-security formatters — the cross-observer ones
                           (compose, docker-run, k8s, oci, json, compose-patch,
                           compose-lint-profile) plus each observer's compose-security
                           renderer (fs/device/capadd/privileged), which all share the
                           compose-patch + lint-profile machinery
  verify/                  `csd verify` (sidecar-vs-sidecar + run mode)
  cli/                     run(), flag definitions, --observe/--format dispatch, per-observer wiring
  obstest/                 test-only helpers shared across observer test suites
                           (imported only from *_test.go, never in the binary)
gadgets/                   (reserved) csd-authored BPF gadgets: source + build/sign/distribute
```

## Import-direction rules

Dependencies point **down only**. The compiler enforces this; a cycle is a
design error, not something to break with an interface as a workaround.

```
cmd/csd
  └→ internal/cli
        └→ internal/verify, internal/format, internal/observe/*
              └→ internal/attrib, internal/ig
                    └→ internal/sidecar, internal/exit
```

- **Foundation (`exit`, `sidecar`, `ig`, `attrib`) imports no csd package above
  it.** `sidecar` and `exit` are pure leaves. `ig` and `attrib` may import
  `exit`/`sidecar` only. This is why every serialized evidence/recommendation
  type lives in `sidecar` (not in the observer that derives it): the observers
  depend on `sidecar`, so if `sidecar` also depended on an observer's type the
  graph would cycle. The observer owns the *deriving function*; `sidecar` owns
  the *type it returns*.
- **An observer (`internal/observe/<name>`) imports only foundation packages.**
  It must not import another observer, `format`, `cli`, or `cmd`. (One honest
  exception: `capadd` reuses the caps `trace_capabilities` event, so it may
  depend on `caps` for that event type — document any such reuse at the import.)
- **`format` and `verify` import `sidecar` (+ observers for their recommendation
  types), never `cli`/`cmd`.**
- **`cli` wires everything; `cmd/csd` is a thin shim over `cli`.**

## The going-forward rule: a new observer = a new package

Adding an observer is adding **one** `internal/observe/<name>` package that ships
its `event` → `aggregate` → `decide` → `confidence` files (plus its formatter
hooks), depending only on the foundation. The filename convention inside the
package mirrors the four layers:

| file (suffix)        | layer / role                                              |
|----------------------|-----------------------------------------------------------|
| `<name>event.go`     | the typed event + its JSON unmarshalling (Observer input) |
| `<name>observe.go`   | the live/fixture observe pipeline (`produce…Observation`) |
| `<name>decision.go`  | aggregate → recommendation (Aggregator); returns a `sidecar` type |
| `<name>confidence.go`| the observer's confidence rubric (`compute…Confidence`)   |

If a contribution adds an observer but its files land in the repo root, or it
reaches for `os/exec` instead of `internal/ig`, or `cli` grows observer-specific
parsing logic that should sit in the observer package — that is the reviewable
omission this standard exists to make visible.

## Naming

- Package names are short, lower-case, no underscores (`observe/caps`, not
  `observe/cap_observer`).
- Exported identifiers carry no stutter beyond what reads naturally
  (`exit.IGMissing`, `attrib.Opts`, `sidecar.Sidecar`).
- The serialized schema types keep their JSON-tag names; only the Go identifier
  is package-qualified.

## Formatter placement (the settled decision)

Per issue #149: **hybrid.** The shared compose-security formatters
(`compose`, `docker-run`, `k8s`, `oci`, `json`, `compose-patch`,
`compose-lint-profile`) live together in `internal/format`, because every
compose-security observer (caps / fs / devices / privileged / capadd) renders
into that same family. An observer with a **distinct output family** owns its
formatter in its own package — `egress` emits `nftables` / `k8s-networkpolicy`
enforcement rules, which are nothing like the compose-security shapes, so
`egressformat.go` lives in `internal/observe/egress`. The test: if a new
observer's output is just another compose-security section — or reuses the
shared compose-patch / lint-profile machinery in `internal/format` at all — it
belongs in `internal/format` (that reuse is the practical reason `privileged`'s
formatter lives there even though the observer is its own package); if it's a
self-contained new enforcement target like egress's, the observer owns it.

A formatter that builds its fixture from an observation does so through the
observer's **exported producer** (`capadd.ProduceCapaddObservation`, …), never
by reaching into observer internals — so the formatter and its test stay in
`internal/format` without `internal/format` depending "up" on an observer.

## Seams designed in on purpose

These are the load-bearing boundaries that keep the ROADMAP's future work
(issue #149 owner comment) a localized change instead of a sweep:

1. **`internal/` is entry-point-agnostic.** No `os.Exit`, flag parsing, or
   stdout writing may live in `observe/*`, `sidecar`, `format`, or `verify` —
   those belong to `cli`/`cmd`. A future long-running daemon becomes a second
   `cmd/csdd` reusing the same `internal/observe`/`sidecar`/… A flat `main`
   cannot host two binaries; this split can. Litmus test: a trivial second
   entry point can import `internal/observe/<name>` without pulling in flag
   parsing.
2. **`internal/ig` is the signal-acquisition seam.** It abstracts *how* a signal
   is obtained. The LSM-BPF migration (replace the kprobe/kretprobe pair with a
   `SEC("lsm/capable")` hook) or any alternate backend plugs in here, not across
   every observer. Observers depend on `internal/ig`, never on `os/exec`-of-`ig`
   directly.
3. **`gadgets/` is the home for csd-authored gadgets.** When csd ships its own
   BPF gadgets (L7 socket parsing, DHCP semantics, distributed as OCI
   artifacts), their source + build/sign/distribute lives at the top level, and
   `internal/ig` invokes built-in and csd-owned gadgets uniformly. This is a
   separate concern from subprocess invocation; do not retrofit it into an
   observer package.
4. **The observer contract is signal-source-agnostic.** A future observer whose
   signal is *not* an ig gadget (e.g. resource baselines from cgroup stats) must
   fit `internal/observe/<name>` without being forced through `internal/ig`. The
   contract is "derive a recommendation from observed behavior," not "wrap a
   gadget."
5. **`internal/` is deliberate — there is no public API.** Everything is
   `internal/`, so there is no compatibility surface to preserve. If a
   library/SDK surface is ever wanted (embedding the deriver), promote specific
   packages to `pkg/` as a reviewed change; do not pre-expose.
