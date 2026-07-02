# advise_capabilities gadget

An Inspektor Gadget [image-based gadget](https://inspektor-gadget.io/docs/latest/gadget-devel/)
that derives the **minimum Linux capability set each container actually uses**,
by tracing `cap_capable()` and unioning the held capabilities per container.

This is csd's "Door 2" artifact: it moves the capability *signal + mechanical
aggregation* onto Inspektor Gadget's own extension surface (a self-contained,
signable OCI image) so it is not exposed to being commoditized by IG core. The
opinionated derivation — init-window / runc-noise suppression, the confidence
rubric, entrypoint cross-check, and Compose/k8s/OCI formatting — deliberately
stays in the csd / compose-lint **front-end**, not in the gadget.

## What it emits

Two datasources:

- `capabilities` — the raw per-container held-capability bitmap (a
  `GADGET_MAPITER` over an mntns-keyed eBPF map, flushed on stop). Not rendered
  directly; consumed by the WASM operator and available to the front-end.
- `advise` — the WASM operator's output: a Kubernetes `securityContext`
  capabilities block (`drop: [ALL]` + the minimal `add:`) per container — the
  artifact upstream issue #173 asks for. This is the *mechanical* union; the
  front-end reshapes it into Compose/docker-run/OCI forms and applies the
  coverage/confidence judgement before you enforce anything.

### Runtime-setup ("runc") noise

The derived set excludes the container runtime's setup caps via ig's own
container-registration boundary — under `--containername`, the runtime's setup
runs before the container's mount namespace is tracked, so those caps never reach
the gadget. This gadget deliberately does **not** special-case the runtime by
process name (a `comm == runc` filter would be a no-op here and would miss
`crun`/`youki`); explicit whole-host setup filtering is deferred to issue #173.
See the design note in [`../README.md`](../README.md#design-note-runtime-setup-runc-noise).

The confidence rubric, entrypoint cross-check, and evidence sidecar stay OUT of
the gadget (in the csd/compose-lint front-end) so its opinion is scoped to what
an upstream `advise` gadget should own.

## Build / sign / push (Door 2)

```sh
# Build (compiles the eBPF for amd64+arm64 and the Go WASM operator):
sudo ig image build gadgets/advise_capabilities -t ghcr.io/<you>/advise_capabilities:0.1.0

# Sign with the project cosign key (same key that signs csd releases):
sudo ig image sign ghcr.io/<you>/advise_capabilities:0.1.0

# Push:
sudo ig image push ghcr.io/<you>/advise_capabilities:0.1.0

# Run against a live container (needs root: CAP_BPF/CAP_PERFMON):
sudo ig run ghcr.io/<you>/advise_capabilities:0.1.0 --containername my-app
```

> `ig image build` compiles without root; `ig image push` writes the local OCI
> store under `/var/lib/ig` and `ig run` loads eBPF — both need root (or a
> one-time `sudo install -d -o "$USER" /var/lib/ig`). See `dev.md`.

## Relationship to Inspektor Gadget core (Door 1)

IG already ships `advise networkpolicy` and `advise seccomp`, but **not** a
capability advisor. The gap is a long-standing, maintainer-endorsed feature
request — upstream issue **#173 "New Gadget: Capability Advisor"** (open since
2021; a lead maintainer listed *"generate the PodSecurityContext with the right
capabilities"* as the remaining task). This gadget is built to the upstream
advise-family conventions (`advise_seccomp` is the closest template) so it can be
proposed upstream later with minimal rework:

- **This repo (Door 2):** aggregation lives in the bundled WASM operator
  (`go/program.go`) — self-service, no core changes.
- **Upstream (Door 1):** the same aggregation would move to a core
  `generate_capabilitypolicy`-style operator enabled by a datasource annotation,
  exactly as `advise networkpolicy` uses `generate_networkpolicy.enable`.

Before opening a Door-1 PR, revive issue #173 to confirm current maintainer
appetite (it is `priority/P4` and went stale).

## Attribution / licensing

- `program.bpf.c` adapts the `cap_capable` hooking from IG's `trace_capabilities`
  gadget (GPL-2.0) and the per-mntns `GADGET_MAPITER` pattern from `advise_seccomp`.
  It is **GPL-2.0** (required — it uses GPL-restricted BPF helpers).
- `go/program.go` (the WASM operator) is **Apache-2.0**, matching IG's Go code, to
  ease a future upstream contribution.

## Limitations

- Records only *held* capabilities (`cap_capable` returned 0). Denials are not
  emitted — the front-end's `verify` handles the insufficient/over-permissioned
  classification.
- Dynamic-observation floor: only what the workload exercises in the window is
  seen. This is a *signal*, not a correctness proof — the front-end grades
  confidence and surfaces coverage caveats.
