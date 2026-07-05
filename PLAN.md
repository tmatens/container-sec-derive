# v1 Plan — Capability Profile Derivation

## Goal

Given a running container, observe every Linux capability check it makes, and emit the minimum `cap_drop` / `cap_add` configuration that would have satisfied the observed behavior. Output is reviewable, format-flexible, and confidence-tagged.

## v1 user-facing UX

**One-shot CLI**, not a long-running daemon. Daemon shape is a v2 question; one-shot proves the concept with half the surface area.

```
csd observe --image postgres:16 \
            --duration 10m \
            --format compose \
            --workload ./exercises/postgres.sh
```

The `--workload` script is a user-supplied exercise: connect/CREATE/INSERT/SELECT/DROP/restart for postgres, GET/POST + SIGHUP reload for caddy, etc. Without a workload script, the tool only observes what the container does on its own (startup + steady idle), which is rarely sufficient.

Output: a compose-format stanza (default) or a chosen alternative format, plus a JSON evidence sidecar (which capability, which PID, which syscall, when, how often).

### Exit codes

One table so CI integrators don't have to reverse-engineer the behavior:

| Code | Meaning | Source |
|---|---|---|
| 0 | Observation completed; window fully elapsed; drop rate < 1% | `csd observe` normal path |
| 0 | Verify outcome `consistent` | `csd verify` PASS |
| 10 | Verify outcome `insufficient` (new denial) | `csd verify` FAIL |
| 11 | Verify outcome `over_permissioned` (unused caps) | `csd verify` WARN — surfaced as nonzero so CI catches it |
| 20 | Target exited early | `csd observe` |
| 21 | Drop rate ≥ 10% | `csd observe` — profile not trustworthy |
| 30 | IG schema/version mismatch (`SchemaMismatch`) | startup guard |
| 31 | IG binary missing / not executable | startup guard |
| 40 | Target-selection ambiguity (multiple replicas, no `--all-matching`) | startup guard |
| 64 | Usage error (bad flags, missing args) | standard `EX_USAGE` |

Codes 20/21 produce an artifact-with-caveat rather than no artifact: the sidecar still writes, confidence is auto-downgraded or forced to `low`, and the exit reason is captured in the sidecar's `target` or `trace_health` block.

## Architecture

The architecture must accommodate future observers (read_only paths, devices, socket use, etc.) without rewrites. v1 implements only the cap observer; the framework is shaped for the future.

### Layers (bottom-up)

1. **Observer** — eBPF program + userspace handler for one specific kernel signal. v1 ships exactly one: the `cap_capable` observer. Future observers (`writable_path`, `device_open`, `socket_connect`, etc.) plug into this same interface.
2. **Container attribution** — shared layer that maps `(cgroup_id, pid)` → `(container_id, image, image_digest)`. Uses cgroup-ID-keyed metadata cache fed by the runtime's events stream. Docker first (`/var/run/docker.sock` + `/events`); Podman compatibility is a follow-up tracked in #164 (the observation layer is already runtime-agnostic — the work is the docker-CLI inspect/history/mounts calls behind a runtime interface).
3. **Aggregator** — per-observer logic that collapses raw events into a policy artifact. For caps: the set of distinct capabilities observed per image, with per-cap event counts and timing.
4. **Formatter** — emits the policy artifact in a target syntax. v1 ships seven:
   - `compose` — `cap_drop:` / `cap_add:` stanza (default)
   - `compose-patch` — unified diff against a user-supplied compose file
   - `docker-run` — `--cap-drop=ALL --cap-add=...` flag string
   - `oci` — OCI runtime spec snippet
   - `k8s` — `securityContext.capabilities`
   - `json` — the evidence sidecar itself, machine-readable
   - `compose-lint-profile` — YAML entry for contribution to the compose-lint catalog (see "Contribution loop with compose-lint" for the acceptance contract)
5. **Validator (Phase 3)** — re-runs the container with the proposed config and the *same* workload, watches for new `cap_capable` denials, and reports consistency — not general sufficiency. See "Verify semantics" below.

### Layers are enforced by package boundaries

The four layers are not just a convention — they map to Go packages whose import
direction makes the layering load-bearing (a `cmd/csd` shim over `internal/cli`,
foundation leaves `internal/{exit,sidecar,ig,attrib}`, one
`internal/observe/<name>` package per observer, the formatters in
`internal/format`). Imports only point "down" toward the foundation, so the
compiler rejects an observer that calls sideways into another observer or up
into the CLI. The package map, the import-direction rules, and the "new observer
= new package" rule are the code-organization standard in
[docs/organization.md](docs/organization.md) (issue #149); `docs/testing.md`
is its analog for the test suite.

### Three-phase workflow

Borrowed from AppArmor's complain → enforce pattern (and SELinux audit2allow):

1. **Record** — run with no `cap_drop`, observe everything.
2. **Suggest** — emit policy artifact + evidence sidecar. Optionally interactive (per-cap allow/deny prompts with evidence shown — aa-logprof style).
3. **Verify** — re-run with the proposed config and the same workload; confirm no new denials and report which proposed caps went unused.

v1 implements 1 and 2 fully; phase 3 ships in v1 as a separate `csd verify` subcommand.

### Verify semantics

`csd verify` is a self-consistency check, not a correctness proof. It answers one question: **"Under the same workload that produced this profile, does the proposed config work?"** It does not — and cannot — answer "is this profile sufficient for all future runs of this image." Workload coverage is the ceiling on both `observe` and `verify`.

Output must reflect this framing. Results have three outcomes, each with explicit language:

- **Consistent (PASS).** "No new capability denials observed under workload `X` (duration `Ns`). Profile is consistent with this workload's observed behavior. Paths not exercised by the workload are untested."
- **Insufficient (FAIL).** "New denial: `CAP_SYS_PTRACE` (syscall `ptrace`, pid `1234`, comm `strace`, t=3.2s). Proposed profile is insufficient for this workload."
- **Over-permissioned (WARN).** "Profile grants `CAP_X` but no check for `CAP_X` fired during verify. Either trim the profile or extend the workload to exercise the path that needed it."

The WARN case is the quiet-but-important one: a trace may have captured a cap during `observe` that does not re-appear under the proposed config (because the denied path was short-circuited, because observation included init-process noise that got filtered differently on re-run, or because the path is genuinely flaky). Surfacing unused caps gives the reviewer something concrete to act on.

Verify result schema (emitted alongside the evidence sidecar):

```json
{
  "verify_of": "<path to evidence sidecar>",
  "image_digest": "sha256:...",
  "workload": "exercises/postgres.sh",
  "duration_seconds": 600,
  "outcome": "consistent | insufficient | over_permissioned",
  "new_denials": [
    { "cap": "SYS_PTRACE", "syscall": "ptrace", "pid": 1234, "comm": "strace", "offset_ms": 3200 }
  ],
  "unused_caps": ["FOWNER"],
  "caveat": "Validates self-consistency under the recorded workload only. Paths not exercised by the workload are untested."
}
```

The `caveat` field is hard-coded in the tool and always emitted. It exists precisely so downstream consumers (CI pipelines, compose-lint contribution flow, humans skimming) cannot accidentally promote "verify passed" to "profile is correct."

### Workload coverage

Workload coverage is the ceiling on correctness for both observation and bisection. A cap check that the workload never triggers is invisible to both methods — they are not independent measurements. v1 addresses this directly rather than treating it as a disclaimer.

**Three mechanisms, all shipping in v1:**

1. **Entrypoint cross-check (automatic).** At observation start, `csd` inspects the image's config (`docker inspect`) and the entrypoint / CMD script contents for capability-correlated signals. The heuristics are small and explicit:

   | Signal | Expected caps |
   |---|---|
   | `chown` / `chmod` in entrypoint | CHOWN, FOWNER, DAC_OVERRIDE |
   | `gosu` / `su-exec` / `setpriv` | SETUID, SETGID |
   | `setcap cap_xxx=+ep` in Dockerfile history | the named cap, explicitly |
   | `mount` / `umount` in entrypoint | SYS_ADMIN (flag for v0.5 dangerous-cap validator) |
   | `ping` / ICMP tooling | NET_RAW |
   | `bind()` to port < 1024 in entrypoint | NET_BIND_SERVICE |

   The entrypoint-expected set is recorded in the sidecar as `expected_caps_from_entrypoint`. This is a **proxy**, not a coverage measurement — it catches the most common "workload didn't exercise initdb" class of gap without requiring per-image hand-written checklists.

2. **Divergence surfacing.** If `observed ⊉ expected_caps_from_entrypoint`, confidence is forced to `low` and the sidecar records each missing cap as a `coverage_warning`:

   ```
   coverage_warning: entrypoint references `chown` but CHOWN was not observed.
   Likely cause: workload did not exercise the initdb/first-boot path.
   ```

   This converts a silent coverage gap into a loud, actionable warning at the exact moment the user would otherwise commit the profile.

   **v0.1.0-rc phase A (Step 15).** The cross-check ships as an *informational* signal: `expected_caps_from_entrypoint` and `coverage_warnings` are populated, and divergence contributes a single `moderate:` hit to the rubric (stacking with any other moderate pushes the grade to `low`), but the force-`low` rule above is not yet wired. Rationale: the heuristic table's false-positive rate is unmeasured until reference-image bisections run. Phase B flips the `moderate:` hit to `low:` (matches the PLAN shape above) once we have signal-quality evidence from those runs; if the signal proves noisy, the whole cross-check is removable by deleting `entrypoint.go` and leaving the sidecar fields as always-empty arrays (no schema break). The `compose-lint-profile` formatter's `coverage_warnings`-empty gate is independent of this phase: it reads the populated warnings directly and refuses to emit on divergence regardless of grade pressure.

3. **Steady-state detection (retained).** No new distinct capability in the final `max(60s, 25% of duration)` contributes one confidence factor. Kept as-is; it's a useful signal for "within the paths the workload exercised, we've converged."

**What v1 explicitly does not do:** grade workload coverage itself. A probe-manifest (`probes.yaml`) that enumerates expected behaviors per reference image is v2 work and already has a forward-compat placeholder in `testdata/<image>/probes.yaml`. The entrypoint cross-check is the v1 proxy; the probe manifest is the v2 generalization.

### Target selection and restart handling

The relationship between a CLI invocation and the container(s) being observed is load-bearing for correctness. Get it wrong and events leak across containers, attribution drifts on restart, or the user silently observes the wrong workload. v1 rules:

**Target selection.** Three mutually exclusive flags:

- `--container <id-or-name>` — explicit, preferred. An exact id or name is unambiguous even with multiple replicas of the same image running. An **id-prefix** (≥6 chars) is a convenience that can match more than one container; if it matches **more than one**, csd errors with the candidate list (same `ExitTargetAmbiguous` as `--image`) and asks for a longer or exact id rather than silently unioning the matches — `--all-matching` is not an opt-in here, it requires `--image`.
- `--image <ref>` — convenience for the common case. Matches containers by image reference. If **zero** containers match, error and exit. If **more than one** container matches, error with a list of candidates and require the user to disambiguate with `--container` or opt in with `--all-matching`.
- `--all-matching` — explicit opt-in to observe every running container of `--image <ref>`. Events are aggregated per `image_digest`, not per `container_id`. The evidence sidecar records the replica count and a per-replica event-count distribution so uneven coverage is visible ("replica A: 1,240 events, replica B: 8 events — workload likely did not exercise replica B").

No "follow containers with this label" shape in v1. If it's needed, it lands as a flag, not as implicit behavior.

**Restart handling.** A target container that exits during observation is not a bug but a data point. Default behavior:

- Record the exit timestamp, exit code, and reason (signal / OOM / normal) in the evidence sidecar.
- Retain all events captured up to the exit; do not discard.
- Do **not** auto-follow a new container that happens to share the image ref. Attribution is cgroup-id-keyed; the new container is a different subject. Surface a confidence factor: "target exited at t=Xs; observation window was shorter than requested."
- Exit code from `csd observe` reflects observation completeness: 0 if the full window elapsed without target exit; nonzero with a clear message if the target died early.

Opt-in follow:

- `--follow-restart` — re-attach when a new container with the matching image ref appears. Attribution keyed by `(image_ref, container_name)` across the gap. Gap duration and restart count are recorded in the sidecar. Explicitly opt-in because it changes the semantics of "what was observed" from "one container's behavior" to "a service's behavior across restarts."

**For `csd verify`.** Verify starts a fresh container under the proposed config and runs the recorded workload against it. If that container crashes before the workload completes, verify reports `outcome: "insufficient"` with the exit reason and, if available, the denial that preceded the crash. A missing cap manifesting as "container died before it could do anything" is still insufficiency; the output should make the causal chain legible, not just report "container exited."

**Verify runtime context.** "A fresh container under the proposed config" requires more than the image plus the proposed caps — non-trivial services need env vars, volumes, networks, healthchecks, and `depends_on` to start at all, and missing any of these will produce container-exit outcomes unrelated to capability sufficiency. v1 resolves this explicitly: `csd verify` accepts `--from-compose <path> --service <name>`, reads the service definition, overrides only the capability-related fields, and runs it. Images with no required runtime context (the tailscale reference image; a toy httpbin) can verify without a compose anchor. The constraint is surfaced in verify's `--help` and in its "insufficient" output when the cause is plausibly missing context rather than a missing cap. A `--from-inspect <container-id>` alternative that reconstructs context from `docker inspect` of the original observed container is v2 work and is not a v1 gap; users whose v1 workflow cannot produce a compose file for verify get the observe sidecar without self-verify, which is still a usable artifact.

**Multi-replica verify.** Not in v1. Verify runs against a single fresh container. If `observe` used `--all-matching`, `verify` still emits a single profile and validates it against one replica; the user is responsible for deciding whether merged multi-replica observations apply uniformly to a single-replica verify run. Confidence language in the evidence sidecar surfaces this.

### Output schema

JSON evidence sidecar (canonical artifact; all formatters derive from this).
The example below is a **`--observe caps`** run; it is byte-identical across
versions except `schema_version`/`tool_version`, because the v0.2/v0.3 observer
blocks are `omitempty` and absent on a caps run (see *Schema evolution policy*
below for the additive blocks an `fs`/`devices`/`privileged` run adds):

```json
{
  "schema_version": "1.5",
  "image": "postgres:16",
  "image_digest": "sha256:...",
  "observed_at": "2026-04-19T15:00:00Z",
  "duration_seconds": 600,
  "workload": "exercises/postgres.sh",
  "tool_version": "0.7.0",
  "kernel_version": "6.8.0-...",
  "target": {
    "mode": "container | image | all-matching",
    "selector": "postgres:16",
    "replicas_observed": 1,
    "per_replica_event_counts": { "a1b2c3": 1240 },
    "per_replica_caps": { "a1b2c3": ["CHOWN", "SETUID", "SETGID"] },
    "replica_cap_disagreement": [],
    "restarts": [],
    "follow_restart": false,
    "target_exited_early": false,
    "init_window_suppressed": 2,
    "distinct_comms": 4
  },
  "capabilities": [
    {
      "name": "CHOWN",
      "event_count": 12,
      "first_seen_offset_ms": 230,
      "last_seen_offset_ms": 8420,
      "comm_samples": ["postgres", "initdb"]
    }
  ],
  "expected_caps_from_entrypoint": ["CHOWN", "FOWNER", "DAC_OVERRIDE", "SETUID", "SETGID"],
  "coverage_warnings": [],
  "trace_health": {
    "events_recorded": 1240,
    "events_dropped": 0,
    "drop_rate": 0.0
  },
  "confidence": {
    "level": "moderate",
    "factors": [
      "workload script provided",
      "event count >= 1000 (1240)",
      "comm diversity: 4 distinct non-init comms",
      "observed set covers entrypoint-expected caps",
      "no new caps observed in last 60s",
      "ig kretprobe provided granted/denied verdict (no superset post-filtering needed)",
      "init-process events filtered (first 500ms excluded)",
      "single replica observed for full window; no restarts"
    ]
  },
  "caveat": "BPF-observed profiles reflect only the paths the workload exercised. Not a correctness proof."
}
```

**Schema evolution policy.** `schema_version` follows semver-on-schema: additive, non-breaking field additions within a major (`1.x`); removals or semantic changes bump the major. Formatters accept any `1.x` and ignore unknown fields. Consumers (including the compose-lint contribution flow) must reject unknown majors. Every release ships a `schema_version` test fixture asserting the shape hasn't silently drifted.

The schema is observer-agnostic-ish: each observer adds its own top-level block alongside `"capabilities"`, all `omitempty` so a run that didn't use an observer serializes without its block. This has happened four times so far, all additive within major `1`: `1.1` added the v0.2 fs blocks (`writable_paths`, `fs_recommendation`, `target.replica_write_path_disagreement`); `1.2` added the v0.3 device + privileged blocks (`device_paths`, `device_recommendation`, `privileged_decomposition`, `target.replica_device_disagreement`); `1.3` added the v0.4 `capadd_validation` block; `1.4` added the v0.5 egress blocks (`egress_destinations`, `egress_recommendation`); `1.5` added the v0.6 DNS annotations (per-destination `hostnames` + `dns_resolvers`). Formatters select the relevant section. Adding a new observer's top-level block is an additive change within the current major.

**Per-replica disagreement.** `replica_cap_disagreement` lists any cap observed on fewer than all replicas under `--all-matching`. Non-empty disagreement forces confidence to at most `moderate`; a disagreement of > 1 cap forces `low` (see rubric). This prevents the tool from silently emitting the union of replica cap sets as if every replica needed every cap.

**Init-window accounting.** `target.init_window_suppressed` is the count of capability events dropped by the `--init-window-ms` filter (default 500ms). The same filtering is also recorded as a `confidence.factors` prose string so humans reading the artifact see it at a glance; the counter exists so machines and reviewers can judge whether a sparse derived cap set is workload-minimal or a window-too-wide artifact and retune accordingly.

**Comm-diversity accounting.** `target.distinct_comms` is the count of distinct `comm` values observed across all replicas after the init-window filter. It feeds the comm-diversity factor in the confidence rubric directly; exposing it on the sidecar (rather than keeping it in a private aggregator field) means reviewers can audit the rubric's input from the artifact alone without re-deriving it from `capabilities[].comm_samples`.

## Tech stack — Inspektor Gadget

**Selected:** wrap [Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget)'s `trace_capabilities` gadget via subprocess. `ig run trace_capabilities --output json` provides the event stream; our binary owns the aggregation, formatters, verifier, and CLI. Kernel floor 5.8 + cgroupv2.

### Why IG over Tracee

Both are Apache 2.0, both work on plain Docker, both populate container ID + image name + image digest. The decisive technical difference is the kernel hook:

- **Tracee** attaches a **kprobe at `cap_capable` entry only**. Events fire for every capability *check* but carry no granted/denied verdict — the probe runs before the LSM resolves the access decision. This produces a *superset* of the caps actually held: every cap any LSM, runc init, or ld.so probe ever asked about. Verified in `pkg/ebpf/probes/event_probes.go` (`CapCapable: NewTraceProbe(KProbe, ...)`, no kretprobe sibling). Workable with aggressive userspace post-filtering, but the noise is real.
- **Inspektor Gadget** attaches a **kprobe + kretprobe pair**. The kretprobe captures `event->capable = (PT_REGS_RC(ctx) == 0)` — `ret=0` means the capability was held, anything else means it was denied. Verified in `gadgets/trace_capabilities/program.bpf.c`. We get the verdict natively; no superset post-filtering needed.

bcc's `libbpf-tools/capable.bpf.c` and Tetragon also implement the kretprobe approach. IG is the cleanest of the three for our use case because it ships with container/image enrichment, syscall context, and an `advise` framework already designed for emitting policy artifacts.

### Why IG over building from scratch

Cost of building a clean-room Go + cilium/ebpf daemon was estimated at ~3–5 weeks for v1 plus 1–2 weeks/quarter ongoing kernel-matrix maintenance. Cost of wrapping IG is ~1–2 weeks for v1 plus ~zero ongoing kernel maintenance (IG owns the BPF program and the kernel compatibility surface). The eBPF program is the hardest part to write and maintain; we don't gain anything by reimplementing it. Build-from-scratch only makes sense if (a) we need an output IG can't produce, (b) we need a daemon shape IG can't accommodate, (c) license incompatibility, or (d) IG governance turns adversely. None apply.

### Why IG over Tracee for the multi-observer future

The roadmap plans observers for read_only/tmpfs (v0.2), privileged decomposition (v0.3), Docker socket usage (v0.4), dangerous-cap validation (v0.5), host-network necessity (v0.6), device profiles (v0.7), and egress allowlists (v0.8). For each phase, IG's gadget catalog already covers most of the kernel-side work:

| Phase | IG primitive | Fit |
|---|---|---|
| v0.1 caps | `trace_capabilities` | Direct |
| v0.2 read_only / tmpfs | `trace_open` (path + attribution) | Direct |
| v0.3 privileged decomp | `trace_capabilities` + `trace_open --filter /dev/*` + `trace_seccomp` | Composition |
| v0.4 socket API usage | `trace_open` for socket fd + custom L7 parsing in userspace | Partial |
| v0.5 dangerous cap validator | `trace_capabilities` (event already includes originating syscall) | Direct |
| v0.6 host network necessity | `trace_tcp` + `trace_bind` + custom AF_PACKET gadget | Partial |
| v0.7 device profile | `trace_open --filter /dev/*` | Direct |
| v0.8 egress allowlist | `trace_tcpconnect` | Direct |

IG's `advise` framework (`advise seccomp-profile` is the canonical precedent) is purpose-built for the observe → aggregate → emit-policy pattern. Every future observer becomes "one trace gadget + one advise gadget + our formatters." The shared cgroup→image attribution layer means we don't reimplement container enrichment per observer. Custom gadgets — needed for v0.4 L7 socket parsing and v0.6 DHCP semantics — distribute as OCI artifacts through IG's existing channel; no fork required.

Tracee in contrast offers a 450-event firehose with no policy-emission framework. We'd build the `advise` layer ourselves six times over. Cross-event correlation is easier in Tracee's monolithic model, but extension is much rougher — adding a new observer means PRing into Tracee or running parallel infrastructure.

### Integration shape

```
csd observe ──► subprocess: ig run trace_capabilities --output json --containername <id>
                    │
                    ▼
              line-delimited JSON event stream (ringbuf-backed)
                    │
                    ▼
            aggregator (in-process, Go) ──► canonical schema (see Output schema)
                    │
                    ▼
            formatter (compose | docker-run | oci | k8s | json | compose-lint-profile)
```

`csd verify` runs the same loop a second time with the proposed `--cap-add` set applied to the container, watches for new denial events.

### Runtime requirements

**Supported:**
- Linux kernel ≥ 5.8 with cgroupv2 unified hierarchy (or hybrid with cgroupv2 present)
- Docker ≥ 20.10 — the default + only per-PR-tested container runtime. Podman is selectable via `--runtime podman` (experimental; see the non-Docker note below)
- BTF available at `/sys/kernel/btf/vmlinux` (CO-RE path; all mainstream distros since ~2022)
- `ig` binary vendored in the release artifact (see "IG version pinning" below)

**Privileges required by the `csd` container:** `CAP_BPF` + `CAP_PERFMON` + `--pid=host`, plus mounts of `/sys/kernel/btf/vmlinux:ro`, `/sys/fs/bpf`, and the runtime socket (`/var/run/docker.sock` for Docker; `/run/podman/podman.sock` for Podman).

The `:ro` flag on a socket bind mount constrains the socket *file*, not the Docker/Podman API — any process with the socket has full container-create authority. `csd observe` and today's `csd verify` are both coded to issue only read calls; run-mode `verify` observes a container the user has already restarted under the proposed config rather than creating one itself (a compose-anchored fresh-container mode is planned v1 scope, and would exercise container-create deliberately). Both subcommands run with the same mount and *could* create containers; the distinction is in the code path, not the permission grant. Downstream docs and README wording must not describe the socket mount as "read-only" without this qualification.

Document `--privileged` as a fallback for distros where capability dropping breaks (some Docker Desktop / older containerd combos still demand it); note that this fallback suspends the tool's "no blast radius beyond what's strictly needed" posture, so it's a workaround, not a recommended configuration.

**Explicit non-goals for v1:**
- Kernels < 5.8 (RHEL 7, CentOS 7, Amazon Linux 1, Debian 10 stock). BCC-based approaches could cover these but are out of scope for a tool already dependent on IG. Not a "TODO" — a "won't."
- Cgroupv1-only hosts. Unified or hybrid hierarchy required.
- **Podman — supported via `--runtime podman` (rootful; #164).** The eBPF observation layer is runtime-agnostic (`ig` auto-detects); the only Docker-coupled touchpoints — `inspect`/`history` in the caps observer (`internal/observe/caps/entrypoint.go`) and `inspect .Mounts` in the fs observer (`internal/observe/fs/fsobserve.go`) — are parameterized by the container CLI via `internal/runtime` (`--runtime docker|podman`, default docker). docker and podman share the same commands + `--format` templates (podman's docker-compatible inspect surface). **Validated** by a live podman smoke (`scripts/smoke_podman.sh`, `make smoke-podman`): the synthetic exerciser under rootful podman, asserting ig attaches + attributes podman containers (caps + fs hard gates) and the podman inspect/history/mounts calls parse — green on GitHub's ubuntu-24.04 + podman. It runs on the **every-3-days schedule** (podman is the secondary runtime; this is the heavier cross-runtime check). **Docker remains the default + the only *per-PR*-tested runtime.** **Rootless podman, containerd, and cri-o** are not supported (containerd/cri-o have no docker-compatible CLI; rootless podman is the separate non-goal below).
- **Rootless Podman** specifically — even once rootful podman is validated, cgroup path layout, user-namespace attribution, and non-root BPF privilege requirements differ enough to be separate work; a post-v1 item, not a v1 gap.
- Kubernetes-in-cluster deployment as a DaemonSet. The `--format k8s` formatter is in scope; running `csd` itself inside k8s is not.

**WSL2 / Docker Desktop:** nominally supported — kernel ≥ 5.8 and BTF are usually present on recent WSL2 kernel builds — but "usually" isn't a shippable claim. v1 ships a `make smoke-wsl2` target that runs the reference images inside WSL2 + Docker Desktop and reports pass/fail per image. If `/proc/version` matches `microsoft` / `WSL2`, `csd observe` surfaces a runtime note pointing at `docs/wsl2.md`, which lists known-good WSL2 kernel versions and where BTF has been observed absent.

### IG version pinning and schema stability

The tool wraps `ig`. Its event schema is stable across patch releases but has shifted across minors historically, and IG is mid-migration to image-based (WASM) gadgets — a large enough change that it deserves explicit handling, not a bullet.

**Pinning policy.**
- v1 pins a single IG release (target: latest stable `v0.x` line at v1 freeze). The pinned version is compiled in as `PINNED_IG_VERSION`.
- `csd` calls `ig version --output json` at startup and compares against `MIN_IG_VERSION` and `MAX_TESTED_IG_VERSION`. Outside the window is a hard error with upgrade guidance, not a silent continue.
- Schema parse failures at runtime exit with a `SchemaMismatch` error naming the detected IG version, the field that failed, and the expected schema. No partial results are emitted.

**Compatibility test fixtures.** `testdata/ig-versions/<version>/trace_capabilities.ndjson` holds canned event samples per tested IG version. Unit tests parse each sample against the tool's schema. Bumping the pin is: add a new version directory, regenerate samples, re-run the v1 reference-image smoke, commit. CI refuses bumps that change sample output without an explicit parser update.

**Contingency for gadget-format churn.** If IG deprecates `trace_capabilities` in favor of an image-based gadget equivalent during v1's life, we do not follow immediately. The tool's container image keeps the last-compatible `ig` pinned; we evaluate the new gadget on its own timeline and ship the migration as a minor release once the compatibility matrix is rebuilt. Users on the old version remain functional; new users get the upgrade when it's ready. This is a bounded, written-down fallback — not a scramble.

### Confidence scoring

The evidence sidecar emits `confidence.level` as `high` / `moderate` / `low`. The grade is mechanical — reviewers should be able to reproduce it from the `factors` list. Raw duration is a weak signal (a 10-minute idle container tells you nothing); the rubric uses event count and comm diversity instead, with duration as a soft floor only.

**High — all of:**
- Workload script provided and referenced by path in the sidecar.
- Event count ≥ 1,000 `cap_capable` events (post-init-filter).
- Comm diversity: ≥ 3 distinct `comm` values across events, excluding init-process filter window.
- Observed cap set ⊇ `expected_caps_from_entrypoint` (no entrypoint-expected cap is missing).
- Steady state reached: no new distinct capability observed in the final `max(60s, 25% of duration)`.
- Event drop rate = 0.
- Target did not exit early.
- Observation duration ≥ 60 seconds (soft floor; prevents degenerate "one second, 1000 events" grades).
- Single replica, or `--all-matching` with no replica below 10% of median event count and `replica_cap_disagreement` empty.

**Moderate — High except exactly one of:**
- No workload script provided (startup + idle only).
- Event count 100–999.
- Comm diversity = 2.
- Event drop rate > 0 but < 1%.
- Steady state not reached.
- `replica_cap_disagreement` contains exactly 1 cap.

**Low — any of:**
- Observation duration < 60 seconds.
- Event count < 100.
- Comm diversity < 2.
- Observed set missing a cap from `expected_caps_from_entrypoint` (`coverage_warnings` non-empty).
- Event drop rate ≥ 1%.
- Target exited early with a non-normal exit reason.
- `replica_cap_disagreement` contains > 1 cap.
- Two or more Moderate conditions simultaneously.

Every condition that fires adds a factor to the sidecar's `factors` array. A user auditing a profile can trace the grade back to the evidence deterministically. New conditions are added to the rubric and applied uniformly — never special-cased per image.

### Event-loss reporting

IG is ringbuf-backed; bursty workloads can overrun the buffer. The tool must surface drops, not hide them:

- **Source at the pinned release (v0.51.0):** ig does not emit a typed `trace_health` event on stdout. Ringbuf losses arrive as logrus-formatted stderr warnings of the form `msg="reading event: lost N samples"`. csd parses the stderr stream with a regex and sums the counts; `events_recorded` is the aggregator's own parsed-and-matched count. Step 11 surfaced this — a prior assumption that ig would post a typed counter on stdout was wrong and produced silent zero-drop reports.
- Always record `events_recorded`, `events_dropped`, and `drop_rate` in the evidence sidecar under a new `trace_health` block.
- Drop rate > 0 adds a confidence factor naming the rate.
- Drop rate ≥ 1% automatically downgrades confidence one level (see rubric above) and emits a stderr warning at observation end — not buried in the JSON, visible in the terminal.
- If drop rate ≥ 10%, `csd observe` exits nonzero with guidance to shorten the observation window or filter the workload. A 10%-dropped profile is not trustworthy enough to quietly emit.
- **Host-wide pressure is real, not hypothetical.** The Step 11 spike on a busy production host saw ig emit ~46–57k lost-sample warnings over 60s — entirely because the default `trace_capabilities` gadget hits cap events for *every* container on the host and the BPF ringbuf overflows. The 10% abort threshold will fire constantly on such hosts unless we either (a) push the container-filter down into the gadget so only the target's events traverse the ringbuf, or (b) widen the ringbuf via ig flags. Option (a) is the v1 path; tracked as a v1 must-have, not a future nice-to-have.

### Future: LSM-BPF migration

The cleanest long-term hook is `SEC("lsm/capable")` BPF-LSM — single hook, native verdict semantic (LSM hooks return the access decision directly), no entry/exit pair, no per-pid scratch map. Kernel ≥ 5.7 with `CONFIG_BPF_LSM=y`. Ubuntu enables it; RHEL only recently. No OSS tool currently ships this for capability observability — would be a clean upstream contribution to IG when distro support justifies dropping the kretprobe path. Tracked in ROADMAP.md as a stretch enhancement.

## Validation methodology

Ground truth for "did the tool produce the right answer?" is **bisection from `cap_drop=ALL`**, not comparison against a human-curated set. The kernel is the validator: if the workload runs cleanly under the bisected minimum, that set is — by definition — sufficient for that workload. Matching a compose-lint curated profile is a secondary cross-check, not the primary correctness signal.

Layers in order of authority:

1. **Bisection (ground truth).** Start the container with `--cap-drop=ALL`. Run the workload. When a `cap_capable` denial occurs (or the workload fails), add the denied cap and restart. Repeat until the workload completes with zero denials. The resulting set is the kernel's own answer for this workload + image digest.
2. **BPF observation (this tool).** Should equal the bisected set. A subset indicates a trace gap (init filter too aggressive, event loss, timing); a superset indicates noisy userspace filtering. Either outcome is a bug to investigate.
3. **Sufficiency smoke (`csd verify`).** Re-run the workload under the proposed config and confirm no new denials. Validates self-consistency, not general sufficiency — only as strong as the workload's coverage.
4. **Static analysis of the entrypoint (smell check).** `gosu`/`su-exec` implies SETUID/SETGID; `chown` implies CHOWN/FOWNER/DAC_OVERRIDE; `setcap cap_xxx=+ep` in Dockerfile means that cap explicitly. Useful for flagging suspicious divergence (bisection says no CHOWN but the entrypoint does `chown` — did the workload exercise initdb?), never as primary derivation.

Documentation is deliberately omitted from this list. Upstream docs are often absent and sometimes overly permissive (e.g., "needs SYS_ADMIN" when only `mount()` is used). They're fine as workload-design hints — "what behaviors should my exerciser trigger?" — but not as a correctness reference.

**Bisection and observation are not independent measurements.** They share the workload: a cap path the workload never exercises is invisible to both. Agreement between them validates execution fidelity (the tool captured what the kernel saw), not coverage (the workload saw everything worth seeing). The independent signals that *do* exist are (a) the entrypoint cross-check (Architecture → Workload coverage), which flags the most common gap class automatically, and (b) the compose-lint curated-profile cross-check (v1 success criterion), which is a hand-curated reference — imperfect, but genuinely independent. v1 success criteria weight both explicitly so neither gets lost as "secondary."

Reference-image selection matters for the same reason (below): small, exercisable surface areas give the workload a chance to hit every path.

### Bisection minimizer: 1-minimal vs. globally minimum (issue #32)

`scripts/bisect_caps.sh` reduces the Docker default cap set to a minimum sufficient set in two phases: a **greedy** single pass (remove each cap in turn; keep it only if removal breaks the workload), then a **stabilization fixpoint** that re-tests every still-kept cap against the *current, smaller* keep set until a full pass drops nothing. The fixpoint is the fix for greedy's order-dependence: a cap tested while the keep set was large can be locked in even though it is unneeded once other caps are later dropped (e.g. cap A is only needed while cap B is present; if B is dropped after A is tested, plain greedy never re-tests A). The result is robustly **1-minimal** — no single cap can be removed without the workload failing — independent of elimination order.

1-minimal is *not always* the **globally minimum-sized** set. They diverge only under (a) **substitutability** — a code path satisfied by either of two caps, so the minimum size is right but the *identity* of the kept cap depends on order — or (b) genuinely **cap-dependent behavior** (a non-monotone workload that takes a different, differently-privileged path when a cap is absent). True globally-minimum requires searching subsets beyond the kept set — exponential in the 14-cap default (2¹⁴ trials × minutes-per-trial), infeasible. Two bounded, opt-in tools approximate it: `ORDERS=N` runs the minimizer from N shuffled orders and flags substitutability (logged + a `substitutable` field on `ground_truth.json`) when results diverge, keeping the smallest; `VERIFY_MINIMAL=1` exhaustively tests every proper subset of the (small) kept set to *prove* 1-minimality and to surface a non-monotone workload (a passing proper subset) rather than silently trust an ambiguous "minimum".

For the current reference images (postgres/caddy/tailscale) the kept caps cover distinct kernel paths and are non-substitutable, so 1-minimal == globally minimum and the stabilization pass produces no drops — the existing `ground_truth.json` sets are unaffected. The minimizer is oracle-driven (the "does this set work?" predicate is pluggable via `CSD_BISECT_ORACLE`), and `scripts/bisect_caps_selftest.sh` (`make bisect-selftest`, gated in `ci.yml`) validates the greedy+stabilization, substitutability detection, and `verify_minimal` logic **hermetically** with synthetic oracles — no Docker — since the real container-driven bisection (`make ground-truth-*`) is dispatch-only.

## Foot-guns to design around

Documented up front because they're easy to miss in implementation:

- **Init-process noise.** Capability checks from `runc:[*]` during container init are not part of the workload's true requirement set. Filter events by comm or by the first N ms of container life (configurable; default 500ms). IG's `--scope container` already drops host-side checks in-kernel; this is the additional userspace filter.
- **Attach-window blindness.** `ig` cannot capture cap_capable events that fire before its BPF programs are loaded and attached. For images whose privileged operations happen once during entrypoint setup — `bind(:80)` for caddy, `gosu` user-switch for postgres — the kernel never re-asks the question during steady-state, so `csd observe` derives `[]` even though the bisected truth is non-empty. Bisection ("drop the cap, restart the container, see if the workload fails") owns this case because it covers the full container lifetime. v0.1 documents the limit (`docs/known-deltas.md` postgres + caddy entries are the canonical examples) and gates against shipping such runs as profiles via the confidence ≥moderate floor on `compose-lint-profile`. A future restart-aware mode (attach `ig` first, then `docker start` the container so init falls inside the window) would close the gap; not in v0.1.
- **Opportunistic-cap divergence.** Some binaries try a privileged code path when the cap is held and silently fall back when denied — tailscale uses `CAP_NET_RAW` for ICMP DERP probes but falls back to UDP, so bisection reports NET_RAW as "not required" while observation correctly captures the attempted surface. The two methods answer different questions: bisection answers "minimum strictly required for workload success," observation answers "cap surface the binary chose to exercise." Both are correct. Until a sidecar field distinguishes them in-band, treat divergence in this direction (observation > bisection) as informative rather than as an error; `docs/known-deltas.md` tailscale entry is the canonical example.
- **Silent coverage gaps.** A cap check the workload doesn't trigger is invisible. Addressed by the entrypoint cross-check (Architecture → Workload coverage) and by steady-state detection; neither is a full coverage proof. "Verify passed" means "consistent with this workload," nothing more — the `caveat` field in the verify result is always-emitted and hard-coded so downstream consumers cannot strip it.
- **Startup vs steady-state differ.** Users can scope recording windows (`--from-startup`, `--steady-state-only`, `--exclude-init-ms 500`).
- **Digest, not tag, is the identity.** Profile entries derived under one digest are not transferable to the next bump without re-validation. Both are recorded in the sidecar; the compose-lint profile format pins the digest.
- **Trace-derived profiles miss rare paths.** Docker's default seccomp profile was hand-curated, not auto-generated, for this reason. Output must encourage human review, not be applied blindly — which is why bisection is the correctness check rather than the curated reference (the curated reference can be wrong too, in either direction).
- **Never emit binary artifacts.** Always reviewable YAML/JSON. Operators must be able to read and edit before applying.
- **Multi-replica event bleed.** Default `--image` matching errors out on ambiguity. `--all-matching` records per-replica cap sets and surfaces disagreement explicitly — silently emitting the union of replica cap sets would pretend every replica needs every cap.
- **Restart-driven attribution drift.** A container exiting mid-observation and a new one starting under the same image ref are two different subjects. v1 does not auto-follow; `--follow-restart` is opt-in and records the gap.
- **Silent event loss.** Ringbuf overruns produce a shorter profile, not an error. The `trace_health` block + stderr warning + auto-confidence-downgrade + nonzero exit at ≥10% together ensure drops cannot silently yield an under-permissioned profile.
- **Confidence grade drift.** The rubric is mechanical on purpose. Resist per-image exceptions — every one weakens the grade's meaning until it becomes decorative.
- **Tool-posture vs tool-purpose tension.** `csd` requires the privileged mounts and caps it later helps users eliminate. That's fine for a one-shot observer with read-only socket access; it would not be fine for a long-running daemon with write access. Do not regress this in v2 daemon design without explicit security review.
- **IG version churn.** Covered by `PINNED_IG_VERSION` / `MIN_IG_VERSION` / `MAX_TESTED_IG_VERSION` guards and per-version test fixtures; mentioned here only so nobody rediscovers it.

## Decisions (locked)

Locked calls. Reversible if evidence emerges, but the defaults stand.

1. **Shape:** one-shot CLI for v1. Daemon revisited in v2.
2. **Output formats shipped in v1:** `compose`, `compose-patch`, `docker-run`, `oci`, `k8s`, `json`, `compose-lint-profile`. `compose` is the default. `json` evidence sidecar is always emitted alongside whichever human-readable format is requested. k8s is in v1 (not deferred) because the derived-profile contribution loop must reach k8s-shaped consumers too.
3. **License:** MIT. Matches compose-lint. `LICENSE` at repo root; README and module metadata reference it.
4. **Repo home:** personal namespace (`github.com/tmatens/container-sec-derive`). Transfer to an org if the project grows beyond solo maintenance.
5. **IG integration mechanism:** subprocess. IG's Go library API is not a stable user surface; subprocess isolation keeps our binary uncoupled from IG's internal refactors. Reconsider only if a v1 requirement needs access that the CLI doesn't expose.
6. **IG binary shipping:** vendored in the release artifact, not fetched at runtime. Reproducibility and offline operation matter more than image size for this tool's use cases.
7. **Relationship to IG upstream.** `csd` is a product wrapper around IG; it is not an IG fork and it is not an upstream `advise` gadget. IG's `advise seccomp-profile` is the template for how a capabilities analog could eventually land upstream, but the scope that belongs in `csd` — seven output formatters, `verify` with self-consistency semantics, deterministic confidence rubric, entrypoint cross-check, compose-lint contribution format — is product, not infrastructure. An `advise capabilities` gadget is tracked in ROADMAP as a post-v1 contribution opportunity. v1 ships `csd` against pinned IG releases; upstream contribution is decoupled from v1 delivery.
8. **Scope lock:** v1 covers capabilities only. Read-only / tmpfs, privileged decomposition, device profiles, egress, and everything else live in ROADMAP and do not influence v1 architecture beyond "the observer/attribution/aggregator/formatter split must accept them later without rewrite." Scope creep into a second observer before v1 ships is explicitly off the table.
9. **Compose-lint contribution contract lives here.** The acceptance bar for derived profiles (`validated_via`, digest, workload, duration, confidence floor) is defined in this repo as part of the `compose-lint-profile` formatter contract (see "Contribution loop with compose-lint"). A corresponding `compose-lint/CONTRIBUTING-PROFILES.md` is a *receiving-side* doc, nice-to-have, but `csd` v1 does not block on it. If compose-lint eventually tightens its bar, `csd`'s formatter updates in lockstep; the contract does not leak across repos in a way that makes v1 undeliverable.

## Tool posture and distribution

`csd` itself runs with `CAP_BPF` + `CAP_PERFMON` + `--pid=host` + read-only container-runtime socket access. A supply-chain compromise of the published binary would be high-blast-radius. Distribution decisions follow from that.

**Release artifacts:**
- Static Linux binary (`csd_linux_amd64`, `csd_linux_arm64`) for direct install.
- Container image (`ghcr.io/tmatens/container-sec-derive:<tag>`) for "I already run compose-lint in Docker, give me the same shape."
- Both artifacts per release. Users pick based on their workflow.

**Supply-chain controls for v1:**
- **Signing:** cosign signatures on both binary and image. While the project is unpublished (employer COI), signing is **key-based with `--tlog-upload=false`** (project key `cosign.pub`; secrets `COSIGN_PRIVATE_KEY`/`COSIGN_PASSWORD`) so nothing hits the public Rekor log — consistent with the COI rule that only *public* exposure is gated. Verification command documented in README (`cosign verify --key cosign.pub --insecure-ignore-tlog …`). When the project goes public, switching to keyless (Sigstore / GitHub OIDC + Rekor) is a deliberate, reviewable change. Unsigned artifacts are not released.
- **SBOM:** generated with `syft` at release time, published alongside artifacts in SPDX + CycloneDX JSON. Listed in the release checksums manifest.
- **Checksums:** `SHA256SUMS` per release, itself cosign-signed.
- **Vendored `ig` provenance:** the vendored IG binary is pinned to a specific upstream release SHA. Its cosign signature is verified **at pin time** by `scripts/refresh-ig-pin.sh` (against IG's freshly fetched key), which commits the verified `SHA256SUMS` under `ig-pin/`; the image build then re-fetches the tarball at build time and verifies it offline with `sha256sum -c` against that committed, cosign-verified-at-pin-time manifest — no cosign runs in the builder. The IG version and its upstream per-arch digests are recorded as a dedicated cosign **attestation on the image** — the `ig-provenance` predicate (type `…/attestations/ig-provenance/v1`), emitted deterministically from the committed pin by `scripts/gen-ig-provenance.sh` and attested in `release.yml`; this is preferred over mutating syft's image SBOM (which catalogs `ig` as a Go binary but not the upstream artifact digests or that the pin is cosign-verified). The predicate is gated at PR time by `TestIGProvenancePredicate`. Both stages fail closed — cosign at pin time, `sha256sum -c` at build — with no fallback download path and no "I'll just grab the latest" escape hatch.
- **Reproducible builds:** goal, not hard requirement for v1. Pinned Go toolchain, `-trimpath`, vendored IG binary at a pinned SHA. Document current reproducibility status honestly in `docs/releases.md` rather than overclaiming — specifically, "signed" and "reproducible" are distinct properties and must not be conflated in release notes.

**Threat model (one paragraph, not a full assessment):** if a compromised `csd` runs against a target container, it can read the target's process state and attach arbitrary eBPF programs with the privileges granted. It also has whatever the mounted container-runtime socket exposes — which, for the Docker and Podman sockets, is full container-create-and-mutate authority regardless of whether the bind mount is `:ro` (the `:ro` constrains the socket file, not the API). `csd observe` and today's `csd verify` both issue only read calls; run-mode `verify` observes a container the user has already restarted under the proposed config rather than creating one itself (a compose-anchored fresh-container mode is planned v1 scope, and would exercise the write surface deliberately). Either way, the *capability* granted to the process is root-equivalent on the host. Users treating `csd` as "untrusted until verified" should run it against throwaway infrastructure first and verify signatures before production use. Short statement: this tool's blast radius equals any other privileged BPF + Docker-API tool on the host.

**Compose-lint contribution bar.** The acceptance contract for derived profiles is owned here (see Decisions item 9 and "Contribution loop with compose-lint" below), not cross-repo. Summary: `validated_via` lists `bpf-observation` + `ci-smoke`, image digest recorded, workload script committed, confidence ≥ `moderate`, reviewer spot-checks one cap against the entrypoint cross-check. Profiles below the bar land in an `exploratory/` path in the receiving catalog, not the main one.

## Reference images and ground-truth fixtures

Three reference images carry the v1 correctness story. Each ships in-repo with a workload script, a bisected ground-truth cap set, and the image digest the bisection was performed against.

```
testdata/
  postgres/
    workload.sh           # exerciser (connect, CREATE, INSERT, SELECT, DROP, restart)
    ground_truth.json     # { image_digest, caps[], bisected_at, bisection_log }
    probes.yaml           # (v2 forward-compat; empty placeholder for v1)
  caddy/
    workload.sh           # GET, POST, SIGHUP reload
    ground_truth.json
    probes.yaml
  tailscale/
    workload.sh           # userspace networking; no privileged caps expected
    ground_truth.json
    probes.yaml
```

Images were chosen because they have **small, exercisable surface areas** — not because they have good documentation. Opaque-workload images (proprietary apps, ML training, anything where we can't write a high-coverage exerciser) are poor ground-truth candidates regardless of documentation quality, and belong in exploratory/low-confidence territory after v1.

`ground_truth.json` is regenerated by a `make ground-truth` target that runs the bisection loop. Bumping an image digest invalidates its ground truth and requires a re-run.

## v0.1 build order

v1 success criteria describe the finished shape, not the first thing to build. Shipping everything at once is the failure mode this section exists to prevent. Ordering:

1. **v0.1.0-alpha — "does it work at all."** Subprocess `ig run trace_capabilities`, parse line-delimited JSON events, filter to one container by id, print the distinct cap set to stdout, exit. No formatters, no verify, no sidecar, no entrypoint cross-check, no confidence rubric. Ship against postgres only. The purpose of this milestone is to validate three load-bearing assumptions before any breadth work: (a) kretprobe pairing is deterministic enough on the reference workloads to hit the <0.1% miss rate the success criteria require; (b) cgroup-id attribution is stable across the lifetime of the observation and invalidates correctly on container exit; (c) the 500ms init filter (or whatever replacement) actually isolates init noise without dropping real workload events. If any of these fail on postgres, the remaining plan redirects — to LSM-BPF sooner, to a reconciliation layer, or to a different init-filter shape — *before* formatters and verify are built on top of them. Expected size: a few hundred lines of Go, one week. **As shipped, this validation was deferred into rc as Step 11.1 and then closed on 2026-04-20:** the alpha scaffold was exercised against `testdata/sample.ndjson` via `--fixture` only; the live `observe()` path against real `ig` did not run until rc. Step 11.1 (below) restored schema alignment with pinned ig v0.51.0, pinned the gadget OCI image, fixed the `timestamp_raw` nanosecond decode, and ran live against a postgres container — 1199 events recorded over a 30s window, drop_rate 0, one replica attributed, compose stanza emitted. Assumption (c) — the 500ms init filter — looks tight rather than loose: `init_window_suppressed = 299` but SYS_ADMIN and SETPCAP still attributed to `runc:[2:INIT]` after the window, which is a follow-up for rc (either lengthen the window or shift to a comm-aware filter). Assumptions (a) and (b) are plausibility-level satisfied for postgres; formal kretprobe miss-rate measurement still belongs to the reference-image bisection work.
2. **v0.1.0-beta — "structural close on the aggregate → format loop."** As shipped: canonical JSON evidence sidecar (`--out`), `compose` formatter (default, `--format` flag with the other six returning `EX_USAGE`), deterministic confidence rubric (subset of the full rubric — factors not yet wired are surfaced as `deferred:` entries and cap the grade at `moderate`), exit-code table, init-window filter with `init_window_suppressed` accounting, multi-replica aggregator (`--image` / `--all-matching` with per-replica cap sets and disagreement recorded in the sidecar), `trace_health` counters with the ≥10% abort. No verify, no other formatters, no entrypoint cross-check, no reference-image workloads, no WSL2, no IG version fixtures. Proves the observe → aggregate → format loop against the postgres fixture; the real-image bisection carries into rc.
3. **v0.1.0-rc — "breadth."** First item was **Step 11.1: parser realignment + IG pin (closed 2026-04-20)** — the live-smoke spike (carried forward from (1)) ran against ig v0.51.0 on a real postgres container and surfaced that csd's `capEvent` shape and `trace_health` decode path did not match what v0.51.0 actually emits. csd parsed 0 events out of ~1900/sec. Step 11.1 realigned `capEvent` to v0.51.0's `proc.*` / `runtime.*` envelope, replaced the typed-stdout `trace_health` path with a stderr `lost N samples` parser, formalised `PINNED_IG_VERSION = v0.51.0` with a per-version fixture under `testdata/ig-versions/v0.51.0/`, pinned the trace_capabilities gadget OCI reference to that same version, and fixed the `timestamp_raw` nanosecond decode. Closing smoke on 2026-04-20 recorded 1199 events over a 30s postgres run, `init_window_suppressed = 299`, drop rate 0, one replica attributed — gate passes at plausibility grade. **Follow-ups filed for rc:** (i) observed set (`SETGID, SETPCAP, SETUID, SYS_ADMIN`) diverges from compose-lint's curated `[CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID]` — SETPCAP/SYS_ADMIN are attributed to `runc:[2:INIT]` past the 500ms window, and CHOWN/DAC_OVERRIDE/FOWNER likely fire during postgres data-dir init which the smoke workload didn't re-trigger; (ii) `cap_capable` BPF over-reports because it fires on negative checks too (`capable:false` events) — **resolved in Step 19 (shipped):** `capEvent.Capable` decoded from the kretprobe verdict, aggregator drops `capable:false` post-recorded++ so denials count toward the drop-rate denominator but never enter the derived cap set; absent field defaults to true so legacy hand-rolled fixtures continue to parse; (iii) **resolved in Step 21 (shipped):** added a comm-aware filter that drops events with `comm` matching `runc:*` regardless of the time window; counted toward `init_window_suppressed` alongside the time-window drops. The 500ms time window stays as a complementary filter for non-`runc` init noise (e.g. `ld-linux-*` early in startup). Widening the time window was rejected because it would also suppress genuine early-postgres workload caps. Formal kretprobe miss-rate measurement and bisected ground truth still come later. Then: full formatter slate now shipped — `docker-run`, `json`, `k8s`, `oci`, `compose-lint-profile` (Step 16, shipped with the acceptance-contract gate enforcing digest, workload-readable, duration ≥300s, confidence ≥moderate, empty coverage_warnings, drop rate <1%, empty replica disagreement; `--allow-exploratory` flips to an annotated `exploratory:` block for below-the-bar profiles), and `compose-patch` (Step 18, shipped — stdlib-only minimal compose parser scoped to `services.<name>.cap_drop`/`cap_add`, replaces existing blocks in place, single-hunk unified diff to stdout, `--compose-in <path> --service <name>` required, EX_USAGE on missing file or unknown service); image-digest enrichment + `--workload` flag (Step 17, shipped) — `inspectEntrypoint` now also pulls top-level `RepoDigests` and `applyEntrypointCrossCheck` promotes the matching digest onto `Sidecar.ImageDigest`; the new `--workload <path>` records the user's exerciser path and feeds the confidence rubric's wired (no longer deferred) "workload script provided" factor. Together they unblock the clean (non-exploratory) compose-lint-profile gate for real ≥300s runs against pushed images; entrypoint cross-check phase A (Step 15, shipped) — `inspectEntrypoint` + heuristic table + informational rubric factor; force-`low` on divergence remains deferred to phase B pending reference-image signal-quality evidence (see §Workload coverage item 2); postgres + caddy + tailscale reference images with bisected ground truth (postgres shifted in from beta); `csd verify` with its three outcomes; user-facing surfacing of `--all-matching` replica disagreement and stderr warning for `trace_health` drops above 0 but below the 10% abort threshold (Step 20, shipped — `emitAdvisoryWarnings` runs after sidecar write, before the ≥10% abort check, so both surfaces are visible without colliding with the existing exit-code path); `csd verify` sidecar-vs-sidecar classifier (Step 22, shipped — `csd verify --baseline <sidecar> --observation <sidecar>` reads two prior `csd observe` sidecars, classifies into `consistent` / `insufficient` / `over_permissioned`, emits the canonical `verify_result` JSON to stdout, and exits 0/10/11; insufficient takes precedence over over_permissioned when both apply because a missing cap is the more actionable signal); `csd verify` run-mode (Step 23, shipped — same subcommand accepts the standard observe-mode flags (`--container`/`--image`/`--all-matching`/`--fixture`/`--workload`/`--duration`/`--init-window-ms`/`--ig`/`--inspect-fixture`/`--fixture-stderr`) in lieu of `--observation`; runs an internal observation against the user-supplied target (which they have already restarted under the proposed config) and classifies it against the baseline, saving the user from running observe + capturing the sidecar by hand. The two modes are mutually exclusive. Container-spawning under proposed config (compose-anchored fresh container per §Verify runtime context) remains v1 scope; v0.1-rc lands the classifier plus this one-shot wrapper, and the user-supplied container is what carries the proposed config); postgres reference image bisection (Step 24, shipped — `testdata/postgres/{workload.sh,ground_truth.json,probes.yaml}` plus `scripts/bisect_caps.sh` and a `make ground-truth-postgres` target. Workload exercises connect/CREATE/INSERT/SELECT/DROP plus a SIGHUP reload; bisection runs by elimination from the Docker default cap set (one container restart per cap), with the kernel as validator. Bisected minimum for `postgres:16@sha256:71e27bf60b…13ddf` is `[DAC_OVERRIDE, SETGID, SETUID]`. This is narrower than compose-lint's curated `[CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID]` because the postgres image's `/var/lib/postgresql/data` is already postgres-owned at build time, so the entrypoint's `chown -R` and `chmod 0700` are no-ops on the v16 image and don't fault for CHOWN/FOWNER. The Step 11.1 follow-up (i) observed-set re-check (postgres against compose-lint's curated set under Step 21's runc-comm filter) carries forward into Step 25/26 follow-on or a separate observation-vs-bisection PR — Step 24 establishes only the bisected ground truth, not the observation comparison); caddy reference image bisection (Step 25, shipped — `testdata/caddy/{workload.sh,ground_truth.json,probes.yaml}` plus a `make ground-truth-caddy` target. Workload exercises GET against the default file server, POST `/load` against the admin API to swap the running config (with `CADDY_ADMIN=0.0.0.0:2019` env so the admin API is reachable from the host — caddy:2 binds admin to `localhost:2019` by default and docker port-forwarding can't reach loopback inside the container), then `docker kill --signal=SIGUSR1` to exercise the Caddyfile-reload signal handler. Bisected minimum for `caddy:2@sha256:25cdc846…e562` is `[NET_BIND_SERVICE]` — only the :80 binding is privileged; everything else (file serving, admin API on :2019, SIGUSR1 reload) is unprivileged. The default-config Caddy image runs as root, so binding :80 needs the cap; an alternate workload that overrides Caddyfile to listen on :8080 would bisect to `[]` but would no longer reflect the default-config user experience. Step 25 prefers default-config faithfulness); tailscale reference image bisection (Step 26, shipped — `testdata/tailscale/{workload.sh,ground_truth.json,probes.yaml}` plus a `make ground-truth-tailscale` target. Workload runs the tailscale CLI inside the container against the local API: poll `tailscale status` until responsive (Logged-out is an accepted responsive state — without an authkey the daemon stays unauthenticated but the local API answers), then `tailscale netcheck` (DERP probe, exercises outbound UDP), `tailscale version`, and `tailscale debug daemon-logs --since=1s`. Bisected minimum for `tailscale/tailscale:stable@sha256:dbeff02d…72a6` is `[]` — userspace mode (`TS_USERSPACE=true`) needs zero capabilities. This validates the architecture's "no privileged caps expected" claim and exercises the bisection driver's empty-set correctness. **Caveat:** the bisection-by-elimination driver's candidate set is the Docker default cap list. Non-userspace tailscaled (`TS_USERSPACE=false`) needs `NET_ADMIN` to manage the TUN device, which is *outside* the Docker default starting set, so the driver would silently report a wrong minimum if pointed at non-userspace mode. The Makefile target hardcodes `TS_USERSPACE=true` for this reason; a future expansion of the candidate cap set in `bisect_caps.sh` would be required to bisect the TUN-mode path correctly); local dev-setup doc (Step 27, shipped — `docs/dev-setup.md` covers Go/Docker/kernel prereqs, `ig v0.51.0` install on Linux, what's exercisable without `ig` (bisection runs and `--fixture` paths) vs. what isn't (live `csd observe`, observe-vs-truth comparisons, ig version-pin smoke). Pin source-of-truth is `main.go`'s `PinnedIGVersion`; the doc bumps in lockstep when the pin moves. Unblocks the `csd observe` ↔ bisected ground truth comparison work for any privileged host); known-deltas scaffold (Step 28, shipped — `docs/known-deltas.md` is the file v1 Correctness criterion 1 names as the home for "delta-with-cause" entries. Initial scaffold documents the three bisected-vs-external-curated deltas already known and justified: postgres bisected `[DAC_OVERRIDE, SETGID, SETUID]` vs. compose-lint curated `[CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID]` (CHOWN/FOWNER absent because the v16 image ships data-dir with correct ownership, entrypoint's `chown`/`chmod` no-op on first start), caddy default-config `[NET_BIND_SERVICE]` vs. an alternate `:8080` workload that would bisect to `[]` (default-config faithfulness wins per Step 25), and tailscale userspace-mode `[]` vs. TUN-mode that would need `NET_ADMIN` (driver candidate set is Docker default; expanding it is a follow-up). The `csd observe` vs. bisected truth section is empty pending an actual observe run; structure and acceptable-cause taxonomy are in place); bisection host-context capture (Step 29, shipped — `scripts/bisect_caps.sh` now records `host_context` into ground_truth.json with `kernel` (`uname -r`), `arch` (`uname -m`), `os` (`uname -s`), `docker_server_version` (`docker version --format '{{.Server.Version}}'`), and `cgroup_driver` (`docker info --format '{{.CgroupDriver}}'`); each field falls back to `"unknown"` rather than aborting the bisection if the lookup fails. Existing `testdata/<image>/ground_truth.json` files predate this step and lack the field — they pick it up on next regeneration via `make ground-truth-<image>`. Captured cap sets in those files remain authoritative; no regeneration in this PR because each bisection takes ~5–8 min and the `host_context` addition does not affect bisection correctness on the host they were captured from. Closes the per-host drift gap noted in the Step 24–26 caveats and in `docs/known-deltas.md`'s acceptable-cause list); observe-vs-bisection deltas for all three reference images (Step 30, shipped — `docs/known-deltas.md` gains three entries under the `csd observe` vs. bisected ground truth section, captured 2026-04-27 against `ig v0.51.0`. **postgres**: observed `[]` vs. bisected `[DAC_OVERRIDE, SETGID, SETUID]` — every capable=true event came from `runc:[*:INIT]` (entrypoint `gosu` switch + per-`docker exec` runc setup), correctly suppressed by Step 21's filter; postgres at runtime does not invoke `capable()` for SQL ops. **caddy**: observed `[]` (zero events) vs. bisected `[NET_BIND_SERVICE]` — `bind(:80)` happens once during entrypoint, before `ig`'s BPF programs attach; the curl-only workload triggers no further `capable()` checks. **tailscale**: observed `[NET_RAW]` vs. bisected `[]` — opposite delta direction; tailscale's `netcheck` opens a raw ICMP socket when CAP_NET_RAW is held and falls back to UDP otherwise, so bisection's drop-and-retry mechanic reports it as not required while observation captures the binary's preferred fast path. PLAN.md §Foot-guns gains two new bullets to generalize the patterns: **Attach-window blindness** (postgres + caddy) — `ig` cannot capture cap_capable events that fire before its BPF programs load; bisection covers the full container lifetime and owns this case; future restart-aware mode would attach `ig` first then `docker start`. **Opportunistic-cap divergence** (tailscale) — bisection answers "minimum strictly required for workload success," observation answers "cap surface the binary chose to exercise"; both correct, both informative; treat observation>bisection deltas as informative until a sidecar field distinguishes them in-band. Together these three entries close v1 Correctness criterion 1 (delta-with-cause acceptance) for the observe-vs-truth axis. The compose-lint-profile gate's confidence ≥moderate floor already prevents shipping any of these three runs as profiles — postgres + tailscale graded `low` on `distinct_comms < 2`, caddy graded `low` on event count < 100 — so the deltas are documented inert. No code changes; doc-only); synthetic cap-exerciser fixture (Step 31, shipped — `testdata/synthetic/{Dockerfile,exerciser.c,workload.sh,expected.json,probes.yaml}` plus a `make synthetic-build` target. The image is multi-stage scratch + statically-linked C binary; comm shows up as `exerciser` (no shell, no entrypoint script), keeping Step 21's runc-comm filter from suppressing it. The exerciser loops once per second invoking syscalls that fire `cap_capable()` for a known set: `chown` to a non-current uid (CAP_CHOWN, twice), `chmod` with the suid bit (CAP_FSETID — kernel uid-match short-circuit may skip), `bind(:80)` on loopback (CAP_NET_BIND_SERVICE), and `fork()` + child `setgid(65534)`/`setuid(65534)` (CAP_SETGID + CAP_SETUID). `expected.json` records `expected_caps_minimum = [CHOWN, NET_BIND_SERVICE, SETGID, SETUID]` and `expected_comm = exerciser`. **Runtime requirement:** the container must be started with `--sysctl net.ipv4.ip_unprivileged_port_start=1024` — Docker defaults this sysctl to 0 inside containers, which makes any port bindable without CAP_NET_BIND_SERVICE; restoring the standard Linux 1024 boundary is what makes `bind(:80)` actually invoke the cap check. CAP_FSETID is attempted (chmod with the suid bit) but does not fire — kernel short-circuits the check when current_fsuid matches the file owner (both uid 0). CAP_SYS_ADMIN fires as `capable=false` denials (~2 per cycle, related to setuid()/RLIMIT_NPROC paths) and is correctly dropped by Step 19's filter. **Role:** csd's pipeline regression test. The Step 30 finding that postgres + caddy observe as `[]` was workload-shape (post-attach silence on caps), not csd brokenness; this fixture is the empirical confirmation — `csd observe` against the synthetic exerciser must include every cap in `expected_caps_minimum`, and if it doesn't there's a real csd bug to find. Bisection N/A; the image is contrived to fire caps continuously and has no real workload semantics. No `make ground-truth-synthetic` target for that reason); entrypoint cross-check phase B (Step 32, shipped — `computeConfidence` flips the `coverage_warnings` non-empty case from `addModerate` to `addLow`, closing rc item 10. Decision drove off Step 30 + Step 31 evidence: the heuristic table fires zero positive signals on every reference image (postgres argv = `docker-entrypoint.sh postgres`, caddy = `caddy run --config /etc/caddy/Caddyfile --adapter caddyfile`, tailscale = `containerboot`, synthetic = `/exerciser` — none match the chown/chmod/gosu/su-exec/setpriv/mount/umount/ping table; none of the images use `setcap` in their Dockerfile history either). Force-low is therefore additive and regression-free on every workload csd has run end-to-end; it locks in the rubric's deterministic answer to entrypoint-mismatch ahead of any v0.2+ heuristic expansion (layer-script reading, etc.) that would actually fire signals. `entrypoint.go` is kept in place rather than deleted because `applyEntrypointCrossCheck` also drives `pickRepoDigest` (Step 17 image-digest promotion), which the compose-lint-profile contract gate depends on; gutting just the heuristic-table half would have left the same surface area to maintain. The phase-A test `TestConfidence_CrossCheckWarningsContributeModerate` was renamed/rewritten as `TestConfidence_CrossCheckWarningsForceLow` and the stack-to-low test deleted as its scenario is now subsumed by the force-low rule. `TestRun_InspectFixturePopulatesCrossCheck` updated to assert `low: N entrypoint coverage warnings present` and grade=low. The phase-A "postgres-style scripted entrypoint matches nothing (argv-only, phase A limitation)" test note remains accurate — phase B is a rubric change, not a heuristic-table change); IG version-pin CI gate (Step 33, shipped — `checkIGVersion` promoted from warn-and-continue to a hard `ExitSchemaMismatch` (code 30) when the detected ig is not `PinnedIGVersion`. Closes v1 success criterion 502's "deliberate wrong-version test exits with `SchemaMismatch` and produces no output" half. Fixture-mode is unaffected — `produceObservation` short-circuits to `aggregate()` before `checkIGVersion` runs, so existing `--fixture testdata/ig-versions/v0.51.0/sample.ndjson` paths continue to work without an `ig` binary at all. Failures of `ig version` itself (binary missing, exec error) still flow through to `observe()` and surface as `ExitIGMissing` (code 31); the pin gate is intentionally narrow to the version-string mismatch case so the two error classes stay legible to CI integrators reading `$?`. New tests: `TestRun_ExitCode_SchemaMismatchOnWrongIGVersion` constructs a fake ig binary (a tiny shell script that prints `v0.50.0` on `version`) and asserts csd exits SchemaMismatch with no `--out` sidecar written and no stdout emitted; `TestRun_ExitCode_PinnedIGVersionPasses` is the positive control proving the gate accepts a matching version. Existing fixture-replay tests (`golden_test.go`, `main_test.go`) cover the parser-vs-pinned-fixture half. CI bootstrapped at `.github/workflows/ci.yml` — vet + test + build on ubuntu-24.04, `actions/checkout` and `actions/setup-go` SHA-pinned per CLAUDE.md §Dependency pinning, `go-version-file: go.mod` so the runtime tracks the repo's pinned Go release).
4. **v0.1.0 — "release."** Container image build/sign + ig vendoring (which carries vendored IG provenance into SBOMs), full docs walkthrough. Everything remaining in "v1 success criteria." First three items closed: WSL2 smoke matrix (Step 34, shipped — `make smoke-wsl2` wraps `scripts/smoke_wsl2.sh`, which loops over the four reference workloads (postgres / caddy / tailscale / synthetic), runs each container, observes for `DURATION` (default 30s), writes a sidecar, and asserts pass criteria per image: postgres / caddy / tailscale pass when `events_recorded + init_window_suppressed > 0` (proves BPF attached; observed cap set may be empty per docs/known-deltas.md), synthetic passes when the derived cap set is a superset of `expected_caps_minimum` (CHOWN, NET_BIND_SERVICE, SETGID, SETUID — synthetic is csd's pipeline regression fixture and an empty observation here is a real csd bug). The script accepts `ONLY=postgres,synthetic` for subset runs and is host-agnostic (warns but runs on native Linux too) so a Linux dev box can portability-check the matrix without WSL2. Runtime detection: `produceObservation` calls `noteWSL2IfDetected` on the live observe path (skipped in fixture mode) which reads `/proc/version` and emits a one-line stderr advisory pointing at `docs/wsl2.md` when the kernel banner contains `microsoft` or `wsl2` (case-insensitive). The detector is unit-tested via `looksLikeWSL2` (`TestLooksLikeWSL2`) covering both the older `microsoft-standard` (5.10) banner and the modern `microsoft-standard-WSL2` (5.15+) banner so a banner-format change is caught at CI. `docs/wsl2.md` covers the smoke procedure, prerequisites, known WSL2 specifics (kernel ≥ 5.15 for BTF, Docker Desktop port forwarding into the WSL2 distro, the `/proc/version` matcher), and the gap-reporting flow. v1 success criterion 504 is now satisfied by the "or documents specific gaps" clause — the smoke is mechanically authored and runnable; per-host gap entries land in `docs/wsl2.md` as contributors hit them); cosign release pipeline (Step 35, shipped — `.github/workflows/release.yml` triggers on `v*` tags. Matrix-builds static binaries for `linux/amd64` + `linux/arm64` with `-trimpath -ldflags "-s -w"` and `CGO_ENABLED=0`, generates a sorted `SHA256SUMS` manifest, and uses cosign keyless OIDC (`id-token: write` permission) to sign each binary plus the manifest itself, emitting self-contained Sigstore bundles (`<file>.cosign.bundle`) that include signature, certificate, and Rekor inclusion proof so verifiers do not need to fetch from the transparency log at verify time. Artifacts are uploaded to a GitHub release via `softprops/action-gh-release` with `fail_on_unmatched_files: true` so a missing artifact aborts the release rather than silently shipping a partial set. All third-party actions SHA-pinned per CLAUDE.md §Dependency pinning: `actions/checkout` and `actions/setup-go` pins reused from `ci.yml` (lockstep advancement); new pins for `actions/upload-artifact@v7.0.1`, `actions/download-artifact@v8.0.1`, `sigstore/cosign-installer@v4.1.1`, `softprops/action-gh-release@v3.0.0`. README §Verifying release artifacts documents the `cosign verify-blob` command for both per-binary and manifest-first verification flows. Pre-v0.1.0 builds remain unsigned; first signed release will be `v0.1.0`. Closes the "binary cosign-signed + SHA256SUMS itself cosign-signed" half of v1 success criterion 511; the container image + SBOM halves remain (Step 36 and a follow-up). Workflow not yet exercised against a real tag — no v0.1.0-rc tag exists; first execution is the v0.1.0 release cut. Validation pre-tag is `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"` plus the cross-reference of action SHAs against `gh api repos/<owner>/<repo>/tags`); SBOM generation (Step 36, shipped — `release.yml`'s `release` job gains two `anchore/sbom-action@v0.24.0` steps that scan the source tree (`.`) and emit `csd.spdx.json` (SPDX 2.3 JSON) + `csd.cyclonedx.json` (CycloneDX JSON) into `dist/`. SBOM generation runs before the SHA256SUMS step so both files' digests land in the manifest; the manifest itself remains the single source of truth for "what was in this release." Each SBOM is cosign-signed with the same keyless OIDC flow as the binaries (one bundle per file, identity-equivalent so the same `cosign verify-blob` command works for any artifact). README §Verifying release artifacts gains an SBOM verify example. Vendored `ig` provenance is intentionally NOT yet recorded in the SBOMs — that requires the ig-fetch + cosign-verify step (own follow-up alongside the container image build), and adding placeholder fields would obscure when real provenance lands. Scope rationale: csd has zero non-stdlib runtime deps, so the SBOMs are small but still record the Go toolchain version and the few build-time deps in `go.sum` (currently empty for the runtime, populated only by future test deps if any). Closes the SBOM half of v1 success criterion 511. New SHA pin this step: `anchore/sbom-action@v0.24.0` (e22c389904149dbc22b58101806040fa8d37a610), cross-checked via `gh api repos/anchore/sbom-action/tags`. Workflow remains tag-triggered and unexecuted until v0.1.0 cut; pre-tag validation is YAML lint + action-SHA cross-check); full docs walkthrough (Step 37, shipped — README expanded from a high-level overview into an end-to-end usage doc: `## Building from source` + `## Quickstart` + `## Usage` (target / window / output flag tables) + `## Output formats` (one-line description per formatter) + `## Sidecar` + `## csd verify` (sidecar-vs-sidecar and run-mode) + `## Contributing a profile to compose-lint` (acceptance contract spelled out + `--allow-exploratory` escape hatch) + `## Exit codes` table + `## Documentation` index pointing at PLAN, ROADMAP, and the three `docs/*` files. The pre-existing security-posture, release-verification, and license sections were preserved verbatim. Step 37 also fixed the `csd observe` subcommand-shape gotcha carried over from the prior session handoff: `run()`'s dispatcher previously only handled `verify`, so `csd observe --container x` failed (flag.Parse stops at the "observe" positional and the trailing flags never bind). The fix strips the `observe` keyword symmetrically with `verify` and falls through to the same flag parser the bare `csd --container x` form uses; both forms now work and the dev-setup.md example keeps working as written. Regression test: `TestRun_ObserveSubcommandStripsKeyword` in `main_test.go` invokes `run()` with a leading `observe` arg and asserts the fixture path produces compose output. Also fixed `docs/dev-setup.md`'s `--duration 30` to `--duration 30s` (Go's time.Duration parser requires a unit suffix; bare integers fail). Closes the "full docs walkthrough" axis; remaining v0.1.0 release-work is the container image build + ig vendoring axis); container image + ig vendoring Phase A (Step 38 Phase A, shipped — `Dockerfile` is multi-stage with both bases digest-pinned: builder is `golang:1.22-bookworm@sha256:3d699e4d…` (CGO_ENABLED=0, `-trimpath -ldflags "-s -w -X main.version=$CSD_VERSION"`); runtime is `gcr.io/distroless/static-debian12@sha256:20bc6c0b…` (~2 MB, no shell, no glibc, no package manager). Runtime stage runs `USER 0:0` with a labeled comment in the file header explaining why `:nonroot` is wrong here: csd's entrypoint requests `CAP_BPF + CAP_PERFMON`, which under default Linux ambient/inheritable cap rules cannot be inherited by an unprivileged UID inside the container even when the container itself has those caps; the container security boundary (`--cap-drop=ALL --cap-add=BPF --cap-add=PERFMON`) is the security envelope, not an unprivileged UID. ig binary fetch + verification chain in the builder stage: (1) curl the per-arch tarball from the GitHub release for `IG_VERSION` (build arg, defaulted to `v0.51.0`, extracted at `make image` time from `main.go`'s `PinnedIGVersion` so all three layers — Dockerfile, runtime schema check, committed pin — stay aligned); (2) grep `ig-pin/SHA256SUMS` for the matching artifact line, abort with a pointer at `scripts/refresh-ig-pin.sh` if no line is found (catches an out-of-band IG_VERSION arg); (3) `sha256sum -c` against the line — fails the build offline if the downloaded tarball does not match the committed pin; (4) extract; install `/tmp/ig` to `/out/ig`; smoke `/out/ig version`. There is no fallback download path. The committed pin under `ig-pin/` carries three vetted-at-pin-time artifacts: `inspektor-gadget.pub` (IG's long-lived cosign public key), `SHA256SUMS` (the upstream release manifest for the pinned version), and `SHA256SUMS.bundle` (the cosign signature bundle). `scripts/refresh-ig-pin.sh` regenerates all three by fetching from `github.com/inspektor-gadget/inspektor-gadget/releases/<version>` (version extracted from `main.go`), running `cosign verify-blob` against the *freshly fetched* public key (a key rotation upstream is therefore a deliberate event captured by the diff), and sanity-checking the manifest covers both linux/amd64 and linux/arm64. Bumping `PinnedIGVersion` requires running this script in the same commit. `make verify-ig-pin` runs cosign verify-blob against the committed bundle/pubkey as a self-consistency check before tagging a release. CI surface is a new workflow `.github/workflows/image-build.yml` triggered on PR and push-to-main: per-arch build matrix on native runners (`linux/amd64` on `ubuntu-24.04`, `linux/arm64` on `ubuntu-24.04-arm` — no QEMU emulation, sidesteps the apt-get-under-emulation crash class compose-lint's matching pattern documents), `load: true` plus `push: false`, three smoke tests run against the loaded image: (a) `--version` matches the build-arg-injected `csd_version` (catches an `-ldflags` injection regression that would silently ship `csd dev` under a real tag); (b) bundled `ig version` line contains `PinnedIGVersion` (confirms the sha256-verified extract reached the runtime stage); (c) fixture-mode end-to-end produces the same compose stanza asserted by `TestRun_FixtureMode` in `main_test.go` (catches regressions where the binary works but the image plumbing — file permissions, working directory, distroless runtime quirks — breaks the path). New SHA pins this step: `docker/setup-buildx-action@4d04d5d9486b7bd6fa91e7baf45bbb4f8b9deedd` (v4.0.0), `docker/build-push-action@bcafcacb16a39f128d818304e6c9c0c18556b85f` (v7.1.0); reuses `actions/checkout@de0fac2e…` (v6.0.2) in lockstep with `ci.yml`/`release.yml`. Phase A intentionally does not push, log into a registry, or cosign the manifest — those are Phase B and gated on the publishing-permission decision (employer COI paperwork). Keeping the publish jobs out of `image-build.yml` means there is no path to publish from this workflow even if a `workflow_dispatch` fires it: no registry secrets in scope, no `permissions: packages: write`. Phase A also adds the precursor `--version` flag (`-version`, `--version`, and `csd version` all short-circuit before flag parsing in `run()`), with `var version = "dev"` overridable at link time via `-ldflags "-X main.version=..."` — required for the smoke tests above and useful for the binary release pipeline once tags fire it. Image labels (`org.opencontainers.image.*`) point at the GitHub repo so the prose lives in one place; `.dockerignore` trims the build context to source + `ig-pin/`, dropping `.git/`, `docs/`, `*.md`, `testdata/`, and build outputs. Closes the "container image build + ig vendoring (engineering)" half of v1 success criterion 511; the publish + cosign-sign-manifest half is Phase B (gated on COI clearance)).

**v0.1.0 release-hardening (post-Step-38, #59–#64).** Live-BPF integration CI (`.github/workflows/integration.yml`, #59) observes the four reference workloads on a hosted ubuntu-24.04 runner; an allowlisted, secrets-free PR comment self-reports the verdict (#60) because the Actions log API is unreachable from some clients. The kretprobe miss-rate (capture-deficit) harness (`scripts/kretprobe_missrate.sh`, `make missrate`, #61) plus its CI surfacing and the `tee`-gating trap doc (#62) close the measurement path for Correctness criterion 1. **Measured 2026-06-13** via `workflow_dispatch run_missrate=true` (run 27473114281): both the live-BPF smoke and kretprobe miss-rate jobs passed — capture deficit ≤ 0.1% against the synthetic counting-mode exerciser (the one reference workload that issues an exact, countable cap stream; postgres/caddy observe `[]` post-attach per `docs/known-deltas.md`), satisfying that criterion's "miss rate < 0.1% (measured, not assumed)" precondition. Renovate automerge for low-risk action/digest bumps was enabled (#63) and the synthetic Dockerfile digest-pinned + doc-only PRs exempted from the live smoke (#64). **v0.1.0 shipped 2026-06-14** (release run 27483911054, all jobs green). Step 38 Phase B landed (#70): the multi-arch image publishes to **private** `ghcr.io/tmatens/container-sec-derive`, manifest cosign-signed (key-based, no Rekor), verified against `cosign.pub`, with SBOM + OpenVEX attestations; and the `v0.1.0` tag was cut, producing the signed GitHub Release (binaries + SPDX/CycloneDX SBOMs + `SHA256SUMS`, each `.sig`). Two release-pipeline fixes were needed at first tag: **#73** (pin cosign 2.x — `cosign-installer@v4.1.2` defaults to 3.x, which removed `--tlog-upload=false` / deprecated `--output-signature`) and **#74** (the image-SBOM `anchore/sbom-action` step defaulted `upload-release-assets:true`, exceeding the image-publish job's `contents:read` token; set false). This closes the publish + cosign-sign-manifest half of v1 success criterion 511. **Remaining COI-gated act:** flip GHCR package visibility to public (manual, post-clearance), at which point switching cosign back to keyless (OIDC + Rekor) is a deliberate, reviewable change.

Each milestone has a working end-to-end demo path; none depend on a subsequent milestone's infrastructure. If alpha surfaces that kretprobe determinism on this kernel family isn't good enough, the sunk cost is one week, not three months.

## v1 success criteria

The tool is "v1 done" when every one of these is true. Checkboxes are binary; no partial credit.

**Correctness**
- [x] For each reference image, `csd observe` output **equals** the bisected ground-truth cap set in `testdata/<image>/ground_truth.json`, OR any delta is explained by a recorded cause in the sidecar (`trace_health.drop_rate > 0`, `coverage_warnings` non-empty, init-filter suppression for a known comm). An unexplained subset or superset is a bug. "Delta-with-cause" is acceptable for v1 but each distinct cause must be listed in `docs/known-deltas.md` with reproduction steps; "the tool is non-deterministic" is not a documentable cause. kretprobe miss rate on the reference-image workloads must be < 0.1% (measured, not assumed) before this criterion is considered met. *(Met 2026-06-13: observe-vs-bisection deltas documented with cause in `docs/known-deltas.md` (Step 30); miss rate measured at ≤ 0.1% — see "v0.1.0 release-hardening" above. The miss-rate proxy is the synthetic counting-mode exerciser because the three image workloads observe no countable post-attach cap stream.)*
- [x] Independent cross-check against compose-lint's curated postgres profile (CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID) agrees, or a documented divergence rationale ships with the profile. This is the independent-signal check called out in Validation methodology and is weighted equal to bisection, not secondary. *(Met 2026-07-05, #294: the divergence rationale ships in `docs/known-deltas.md` (postgres bisected `[DAC_OVERRIDE, SETGID, SETUID]` vs. the curated superset — CHOWN/FOWNER are first-boot no-ops on the pre-owned data dir), and `internal/parity` now **enforces** it in the `go test ./...` lane: the set difference between `testdata/postgres/ground_truth.json` and the pinned curated mirror in `testdata/parity/compose-lint-profiles.json` must exactly equal the recorded `accepted_delta`, so neither artifact can silently drift from the documented delta. The mirror is pinned-by-value until compose-lint's automated catalog (compose-lint #360) publishes real derived profiles, at which point `source` re-points at that artifact.)*
- [ ] Entrypoint cross-check produces `expected_caps_from_entrypoint` for each reference image and agrees with observed caps under the committed workload (no `coverage_warnings`).

**Verify**
- [ ] `csd verify` correctly reports `consistent` when re-run under the proposed config. The `caveat` field is present and non-empty.
- [ ] `csd verify` correctly reports `insufficient` with the offending cap when run with an artificially under-permissioned config.
- [ ] `csd verify` correctly reports `over_permissioned` when given a config that grants caps the workload never triggers.

**Output formatters (all seven)**
- [ ] `compose`, `compose-patch`, `docker-run`, `oci`, `k8s`, `json`, `compose-lint-profile` produce valid syntax for their target.
- [ ] `compose-lint-profile` enforces the acceptance contract (digest, duration, confidence, drop rate, coverage warnings, replica disagreement) and refuses to emit when unmet unless `--allow-exploratory` is passed.

**Schema and evidence**
- [ ] Sidecar includes `schema_version` set to `"1.0"` and is additive-stable: adding a second observer in v0.2 does not bump the major.
- [ ] Event-loss reporting end-to-end: sidecar carries `trace_health.events_recorded` / `events_dropped` / `drop_rate`; ≥ 1% downgrades confidence; ≥ 10% exits nonzero. Covered by a synthetic-burst test.
- [ ] Confidence rubric is deterministic: same inputs produce the same grade. Snapshot tests cover High / Moderate / Low transitions including entrypoint-miss → Low and replica-disagreement → Low.
- [ ] Multi-replica: `--all-matching` populates `per_replica_caps` and `replica_cap_disagreement`; disagreement > 1 cap forces `low`.

**Runtime**
- [ ] IG compatibility fixtures (`testdata/ig-versions/<pinned>/`) exist; CI runs the parser against them; a deliberate wrong-version test exits with `SchemaMismatch` and produces no output.
- [ ] Exit codes match the table in "Exit codes" for each documented scenario (covered by integration tests).
- [ ] `make smoke-wsl2` passes on a current WSL2 + Docker Desktop install for all three reference images, or documents specific gaps in `docs/wsl2.md`.

**Architecture forward-compat**
- [ ] Architecture reviewed against the v0.2 (read_only) and v0.3 (privileged decomp) plans; no rewrite needed to add a second observer. Sidecar's top-level array shape accommodates a `writable_paths` sibling without schema-major bump.
- [ ] Workload-script schema reviewed against the v2 daemon probe-manifest shape; a v1 `workload.sh` sits beside a future `probes.yaml` without rewriting surrounding metadata.

**Release & docs**
- [x] Release artifacts (binary + container image) are cosign-signed; `SHA256SUMS` and SBOMs are published; README documents the verification command. *(Met 2026-06-14, v0.1.0 release run 27483911054: signed binaries + SPDX/CycloneDX SBOMs + `SHA256SUMS` in the GitHub Release; private GHCR image manifest cosign-signed + SBOM/OpenVEX-attested; README §Verifying release artifacts documents the verify commands. Signing is key-based `--tlog-upload=false` while unpublished, not keyless — see Supply-chain.)*
- [x] Documentation walks a user from "I have a new image" through observe → verify → `compose-lint-profile` emit → PR. *(Met: README Quickstart → `csd verify` → Contributing a profile to compose-lint covers the full journey.)*

## Contribution loop with compose-lint

The JSON evidence sidecar is directly translatable to a compose-lint catalog profile. The `--format compose-lint-profile` formatter emits exactly the catalog schema (`compose-lint` `profile.schema.json`, Draft 2020-12), ready to PR — an aggregate-per-image document keyed on the normalized `image:`, with each observer's output under its `dimensions.<name>` entry:

```yaml
schema_version: "1.0"                 # catalog schema version (NOT the sidecar's)
image: docker.io/library/postgres     # normalized repo ref, a field not the key
status: validated                     # or exploratory (below the bar)
dimensions:
  capabilities:                       # keyed by dimension, not observer verb
    cap_drop: [ALL]
    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]
    derivation:
      tool: container-sec-derive
      tool_version: "0.6.0"
      sidecar_schema_version: "1.5"   # csd's own sidecar schema, per dimension
      observer: caps
      validated_image: docker.io/library/postgres@sha256:...
      validated_date: "2026-04-19"
      duration_seconds: 600
      confidence: moderate
      workload: profiles/workloads/postgres.sh
      workload_sha256: <sha256 of the committed workload>
      validated_via: [bpf-observation]   # compose-lint CI appends ci-smoke
      observation_backend:
        ig_version: v0.51.0
        gadgets: []                      # {name,image,digest} for csd-authored gadgets
```

**Merge model (decision A, csd#218 §Open decision).** Each `csd` run observes exactly one dimension, so the formatter emits a **single-dimension** document. A full profile is the union of caps + fs + devices + … under one `image`; the catalog automation unions the `dimensions` maps (shared `image`; `status: validated` only if every dimension clears its bar). csd ships no `csd merge` subcommand — decision A keeps the per-run model and matches the automation consumer the trust model assumes (compose-lint ADR-017 §7). The `observation_backend.gadgets` list is empty for the built-in-`ig` observers; a csd-authored gadget must thread its `{name, image, digest}` here once the gadget-migration work lands.

**Acceptance contract (owned by this repo, honored by the formatter).** The formatter refuses to emit a profile entry unless:

- `schema_version` is set and within the current major.
- `image_digest` is present.
- `workload` file path is set and the file is readable at emit time.
- `duration_seconds` ≥ 300 (5 minutes).
- `confidence.level` is `high` or `moderate`. `low`-confidence profiles fail emit with a pointer to the `coverage_warnings` and `factors` that caused the downgrade.
- `coverage_warnings` is empty. (Entrypoint-expected caps must be covered by observation.)
- `trace_health.drop_rate` < 1%.
- `replica_cap_disagreement` is empty. (For `--all-matching` runs, either the replicas agree or the user explicitly picks one.)

A user who wants to contribute a `low`-confidence profile for exploratory review uses `--format compose-lint-profile --allow-exploratory`, which emits the same document with `status: exploratory` and a top-level `acceptance_contract_violations:` list naming every failed check. The receiving catalog decides whether to accept such entries in its `catalog/exploratory/` subdirectory; `csd`'s contract only guarantees the annotation.

**Re-validation on digest bump.** `csd observe` output is deterministic enough for sidecar-to-sidecar diff to drive re-validation:

1. CI pins `image_digest` in the derived profile.
2. On registry digest change, CI re-runs `csd observe` with the committed workload against the new digest.
3. CI diffs the new sidecar's `capabilities[].name` list against the prior profile's `dimensions.capabilities.cap_add`.
4. No diff → profile re-validated, `validated_date` and `validated_image` bumped.
5. Diff → profile is invalidated; human review required; the diff becomes the PR body.

v1 does not ship a `csd drift` subcommand — the diff is a shell one-liner and a dedicated subcommand is premature before real users surface a need. Revisit in v0.1.x if the one-liner proves insufficient.
