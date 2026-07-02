# csd gadgets

Inspektor Gadget (IG) image-based gadgets that supply csd's observation signals
and mechanical aggregation. Each gadget is a self-contained, signable OCI image
built with `ig image build` — csd's "Door 2": the eBPF signal + per-container
aggregation live on IG's extension surface, while the opinionated derivation
(init-window suppression, confidence rubric, volume correlation, multi-format
output) stays in the csd/compose-lint front-end.

## Coverage of csd's dimensions vs upstream Inspektor Gadget

Determined against IG v0.51.0 (issue/PR search + gadget catalog). IG ships only
two advisor gadgets — `advise_networkpolicy` and `advise_seccomp` — plus raw
tracers (`trace_open`, `trace_tcp`, `trace_dns`, `trace_capabilities`, …).

| Dimension | Upstream advisor? | Signal (stock tracer) | Prior art in IG | Decision |
|---|---|---|---|---|
| **capabilities** | none | `trace_capabilities` | issue **#173** OPEN, maintainer-endorsed, never built | **BUILT** → `advise_capabilities` |
| **read-only rootfs + tmpfs** | none | `trace_open` (write-intent) | none (searched) | **BUILT** → `advise_filesystem` |
| **devices** (`/dev` grant) | none | `trace_open` (`/dev/*`) | none (searched) | **BUILT** → `advise_devices` |
| **privileged decomposition** | n/a | — | — | front-end composition of `advise_capabilities` + `advise_devices` (no new gadget; the AppArmor/seccomp facet stays unobservable) |
| **cap_add validation** | n/a | `trace_capabilities` | — | reuses `advise_capabilities`; validation logic is front-end |
| **network egress allowlist** | **`advise_networkpolicy`** | `trace_tcp` + `trace_dns` | shipping | **REUSE** `advise_networkpolicy`; it emits k8s/Cilium NetworkPolicy, so csd post-processes its datasource for Docker/nftables output |
| **seccomp profile** | **`advise_seccomp`** | (syscall recorder) | shipping | **REUSE** `advise_seccomp` (also csd's documented blind spot — out of csd scope) |
| **host-network necessity** | none | `trace_bind` + `trace_tcp` | none (only tracing-support issues #258, #1334, closed) | **DEFERRED** — only a negative/heuristic inference is possible; needs a validated heuristic before building |
| **docker/container-socket API scoping** | none | — | none | **SKIP** — API scoping is L7 HTTP-over-unix-socket; IG has no unix-socket L7 tracer. Only socket *presence* is observable, not operations. (csd issue #110) |

## Built gadgets (this repo)

| Gadget | Emits | Validated |
|---|---|---|
| [`advise_capabilities`](advise_capabilities) | `cap_drop: ALL` + minimal `cap_add` | unit + e2e (CAP_CHOWN container → `cap_add: CHOWN`) |
| [`advise_filesystem`](advise_filesystem) | `read_only: true` + `tmpfs:` dirs | unit + e2e (file-writer → `tmpfs: /var/lib/app`) |
| [`advise_devices`](advise_devices) | minimal `devices:` grant | unit + e2e (`/dev/fuse` opener → grant, defaults excluded) |

All three: eBPF (amd64+arm64) + Go→WASM operator compile via `ig image build`;
pure aggregation host-unit-tested under `go/advice`; live signal verified by
`test/e2e.sh`. CI in `.github/workflows/gadgets.yml` matrixes over them.

## Conventions (built to ease a Door-1 upstream contribution)

Each gadget mirrors IG's `advise_seccomp`: a `program.bpf.c` that aggregates per
mount namespace via `GADGET_MAPITER`, a `gadget.yaml` with a raw datasource
(`cli.supported-output-modes: none`, `ebpf.map.flush-on-stop: true`) plus an
`advise` datasource, and a WASM operator (`go/program.go`) that renders the
recommendation. The opinionated bits are kept OUT of the gadget on purpose.

**Door 1 (upstreaming):** to propose any of these to IG core, swap `go/go.mod`
to the in-tree `module main` + `replace` form and move aggregation from the WASM
operator to a core `generate_*` operator enabled by a datasource annotation,
exactly as `advise_networkpolicy` uses `generate_networkpolicy.enable`. Start with
`advise_capabilities` against the endorsed, unbuilt issue #173 — comment there to
confirm current maintainer appetite before opening a PR.
