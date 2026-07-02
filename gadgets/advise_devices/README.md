# advise_devices gadget

An Inspektor Gadget image-based gadget that derives the **minimal `devices:`
grant** a container needs, by recording the `/dev/*` nodes it opens and excluding
the runtime's default device set.

csd "Door 2" artifact, sibling to `advise_capabilities` and `advise_filesystem`.
The mechanical signal + default-set filtering live in the gadget; correlating the
grant against how a `privileged: true` container was actually using devices, and
multi-format output, stay in the csd/compose-lint front-end.

## What it emits

- `devices` — raw per-(container, /dev path) map iterator, flushed on stop.
- `advise` — a `devices:` grant listing the non-default `/dev` nodes the
  container opened (1:1 host:container mapping the front-end can rewrite), or a
  note that no grant is required. One packet per container.

## Prior art

IG ships **no** devices advisor and none was proposed ("devices advise", "device
advisor", "/dev advise" → zero issues/PRs). It ships the `trace_open` tracer this
gadget's path resolution is adapted from. Greenfield; built to `advise_seccomp`
conventions for a possible Door-1 upstream contribution.

## Build / run

```sh
sudo ig image build gadgets/advise_devices -t ghcr.io/<you>/advise_devices:0.1.0
sudo ig run ghcr.io/<you>/advise_devices:0.1.0 --containername my-app
```

## Attribution / licensing

- `program.bpf.c` adapts full-path resolution from IG's `trace_open` (GPL-2.0) and
  the per-mntns aggregation from `advise_seccomp`. **GPL-2.0**.
- `go/` (WASM operator + `advice`) is **Apache-2.0**, matching IG.

## Limitations

- Records device *opens*; a device the workload never touched in the window is
  invisible (dynamic-observation floor). This pairs with `advise_capabilities` to
  decompose `privileged: true` into `cap_add` + `devices` — but the AppArmor/
  seccomp dimension of `privileged` is not observable here (a documented csd
  limitation).
- The default-device set is Docker's; a runtime with a different default set may
  need the exclusion list adjusted (it lives in `go/advice`).
