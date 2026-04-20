# container-sec-derive

Runtime observation tool that derives the minimum container security configuration an image actually needs by watching it run.

> **Status:** pre-alpha — planning phase. Architecture and v1 scope defined; implementation not yet started.

## What it does

Container hardening config (capabilities, read-only filesystem + tmpfs paths, devices, etc.) is hard to derive statically. The conventional answer is trial-and-error: drop a setting, run the container, watch what breaks, add the setting back, repeat. This tool replaces that loop with eBPF observation.

You point it at a running container; it traces the kernel calls relevant to a given security setting; after a recording window, it emits the minimum config that would have satisfied the observed behavior — in your choice of output format (Compose stanza, `docker run` flags, OCI spec, Kubernetes SecurityContext, JSON).

## Audience

Anyone hardening container security on Docker / Podman / OCI-compatible runtimes. Not orchestrator-specific — the engine observes containers, not Compose files. Compose-shaped output is one of several output formatters.

## Relationship to compose-lint

[compose-lint](https://github.com/tmatens/compose-lint) ships **curated profiles** for known images — fast, offline, instant fix guidance. `container-sec-derive` lets users **derive new profiles** for images compose-lint doesn't yet cover, and contribute them back as PRs to the compose-lint catalog. The two tools form a feedback loop:

```
compose-lint catalog ← PRs with derived profiles ← container-sec-derive
       ↓                                                      ↑
  curated fix:                                       run-it-and-see
  guidance                                                    ↑
       ↓                                                      |
  user runs `compose-lint`  → "no profile for image X" → user runs `container-sec-derive` against image X
```

## v1 scope

**Capability profiles only.** Observe `cap_capable()` checks, attribute per container/image, emit minimum `cap_drop:` / `cap_add:` set. See [PLAN.md](PLAN.md).

## Future scope

Read-only filesystem + tmpfs paths, privileged-mode decomposition, Docker socket usage, dangerous-cap validation, host-network necessity, device profiles, network egress allowlists. See [ROADMAP.md](ROADMAP.md). All future observers slot into the same architecture as v1.

## Out of scope

- **Enforcement.** This tool observes and recommends; it does not enforce policy. (Use AppArmor / seccomp / PSS for that.)
- **Static analysis of images or compose files.** That's compose-lint's job.
- **Build-time / Dockerfile analysis.** Different problem class.
- **Kubernetes-first UX.** K8s output formatter is in scope; K8s-specific deployment isn't a v1 priority. The `--format k8s` formatter exists so derived profiles can be applied to k8s workloads, not because the tool is intended to live as a DaemonSet.
- **Kernels < 5.8, cgroupv1-only hosts, rootless Podman.** See PLAN.md "Runtime requirements" for the full non-goal list.

## A note on the tool's own security posture

`container-sec-derive` needs the very privileges and mounts it later helps you eliminate: `CAP_BPF`, `CAP_PERFMON`, `--pid=host`, and a bind mount of the container-runtime socket. A `:ro` suffix on that bind mount constrains the socket *file*; it does not sandbox the Docker/Podman API. Any process with the socket can create containers, bind-mount `/`, and become root on the host — so treat `csd`'s blast radius accordingly. It is equivalent to running any other privileged BPF + Docker-API tool on the host.

`csd observe` is coded to issue only read calls against the socket. `csd verify` additionally creates a fresh container to re-run the workload under the proposed config, so it exercises container-create authority deliberately. The distinction is in the code path, not the permission grant — both subcommands run with the same mount.

This is not a contradiction with the tool's purpose — `csd` is a one-shot observer, not a long-running service. Run it for the observation window, then stop it. Release artifacts are cosign-signed; verify signatures before use in any environment you care about. See PLAN.md "Tool posture and distribution" for the full threat model and supply-chain controls.

A long-running daemon shape (v2) with these privileges is its own security decision and will not ship without the corresponding review. See ROADMAP.md.

## License

MIT. Matches compose-lint. See [LICENSE](LICENSE).
