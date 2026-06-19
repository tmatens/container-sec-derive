# How csd compares to related tools

Runtime-derived least privilege is **not** an empty category. Observing a workload
and emitting the minimum policy it needs is an idea with decades of lineage and
several active implementations. This page is an honest map of that landscape: who
else does something like what `csd` does, where `csd` overlaps with them, and where
it is actually differentiated.

It exists so a reader evaluating `csd` can answer "how is this different from *X*?"
without us pretending *X* doesn't exist — and so a contributor can see which prior
art to learn from before reinventing it.

The short version: no single public tool produces the same set of artifacts `csd`
does, but **every individual dimension `csd` derives has an established player**,
and one of them — Inspektor Gadget — is the engine `csd` is built on. `csd`'s
defensible niche is the *combination*: a Docker-first, multi-dimensional,
evidence-backed, one-shot CLI whose output drops straight into Compose.

## What "like csd" means here

`csd` is characterised by six attributes at once. Tools are "like `csd`" to the
degree they share them:

1. **Dynamic** — derives from a running workload, not from static manifest/image analysis.
2. **eBPF-based** — observes via kernel instrumentation.
3. **Generates config** — emits a policy/config artifact, rather than only detecting or enforcing.
4. **Container-scoped** — the unit of analysis is a container, not a host process.
5. **Multi-dimensional** — caps, filesystem, devices, `privileged`, `cap_add`, egress in one tool.
6. **Evidence-backed** — signed sidecar, confidence rubric, declared blind spots.

Most peers share three or four. None share all six.

## The closest peers: runtime-observation → least-privilege artifact

These are the true comparison set — observe a running workload, emit a policy.

### Inspektor Gadget `advise` — the one to read first

`csd` **wraps Inspektor Gadget** (subprocess, per the architecture), and IG already
ships its own runtime-derived advisors: [`advise seccomp-profile`](https://www.inspektor-gadget.io/)
(records syscalls → a seccomp profile) and [`advise networkpolicy`](https://inspektor-gadget.io/docs/main/gadgets/advise_networkpolicy/)
(summarises TCP/UDP → a Kubernetes NetworkPolicy).

So the sharpest fair question about `csd` is "what's the delta over `ig advise`?"
The honest answer:

- **Dimensions IG `advise` does not cover.** IG advises seccomp + network policy.
  `csd` derives capabilities (as Compose `cap_drop`/`cap_add`), read-only rootfs +
  `tmpfs:`, device grants, the `privileged: true` → `cap_add` + `devices`
  decomposition, and the dangerous-`cap_add` validation. These are not `ig advise`
  outputs; `csd` builds them from lower-level gadgets (`trace_capabilities`,
  `trace_open`, `trace_tcp`, `trace_dns`).
- **Output shape.** `ig advise` targets Kubernetes resources. `csd` is Docker/Compose-first
  (seven Compose-security formatters; `nftables` for egress) with k8s/OCI as
  additional formatters, not the center of gravity.
- **Evidence + acceptance gates.** The signed sidecar, the confidence rubric, the
  `compose-lint-profile` acceptance contract, and the inverted-risk handling for
  egress are `csd` additions on top of raw observation.

What `csd` does **not** do that IG `advise` does: **emit a seccomp profile.** That's
the `security_opt` blind spot — see [LIMITATIONS.md](LIMITATIONS.md). It is the most
common runtime-derived artifact, and the one `csd` deliberately doesn't produce.

### Kubescape `kapprofiler` / ApplicationProfile

[Kubescape's `kapprofiler`](https://github.com/kubescape/kapprofiler) is
architecturally the closest cousin: it is **also built on Inspektor Gadget + eBPF**,
recording each container's file access, processes, **capabilities used**, syscalls,
and network into an `ApplicationProfile`. Same engine, same "record behaviour into a
profile" bet.

It differs in *purpose and shape*: it is a Kubernetes operator oriented toward
anomaly detection and vulnerability-reachability, not toward emitting paste-ready
hardening config. `csd` is the CLI that hands you the config; `kapprofiler` is the
cluster-resident profiler that watches for drift from the norm.

### Security Profiles Operator (kubernetes-sigs)

[SPO](https://github.com/kubernetes-sigs/security-profiles-operator) is the most
mature "record-from-runtime" project. It records **seccomp, AppArmor, and SELinux**
profiles from running pods, via either a log recorder or an **eBPF recorder**, as
Kubernetes CRDs. It covers exactly the seccomp/AppArmor/SELinux dimensions `csd`
does *not*.

It is the opposite deployment model: a cluster-resident operator with CRDs, versus
`csd`'s one-shot CLI. A Kubernetes shop that wants recorded seccomp/AppArmor/SELinux
should use SPO; `csd` is for the Docker/Compose user who wants caps/devices/fs/egress
config out of a single command.

### SlimToolkit (formerly docker-slim)

[SlimToolkit](https://github.com/slimtoolkit/slim) is the closest in *shape*: a
Docker-centric tool that observes runtime behaviour and auto-generates **seccomp +
AppArmor** profiles (alongside its headline image minification). It is the existing
answer to "a Docker user wants least-privilege profiles from observation."

`csd` differs by the artifacts it derives (caps / devices / `privileged` / fs /
egress, not seccomp/apparmor) and by emitting Compose/k8s config rather than
profiles plus a slimmed image. The two are complementary more than competing: run
SlimToolkit for the seccomp/apparmor profile and a smaller image, run `csd` for the
Compose-level caps/devices/`privileged`/egress hardening.

### oci-seccomp-bpf-hook (containers / Podman)

[`oci-seccomp-bpf-hook`](https://github.com/containers/oci-seccomp-bpf-hook) is an
eBPF OCI hook that traces syscalls during a `podman run` and emits a seccomp
profile. Single-dimension, Podman-native, and folded into the run itself rather than
a separate observe step. Same idea as IG's seccomp advisor, different plumbing.

## The lineage: OS-level "learning mode"

`csd`'s "run it, see what it touches, emit the minimum" loop is the containerised
descendant of host tooling that predates containers:

- **AppArmor** — `aa-genprof` / `aa-logprof`: complain-mode learning → profile.
- **SELinux** — `audit2allow` / `audit2why` / `sepolgen`: observe denials → policy;
  and **udica**, which generates container SELinux policies.
- **BCC / bpftrace `capable`** (tracing `cap_capable`): the raw primitive under
  `csd`'s `caps` observer — the manual version of what the capability observer
  automates.

These matter for honesty about novelty: "least privilege from observed behaviour"
is an old idea. `csd`'s contribution is multi-dimensionality, Compose output, and
the evidence/signing discipline — not the core loop.

## The egress dimension specifically

`csd`'s `egress` observer sits in a crowded network-policy-recommendation field,
most of it Kubernetes-centric:

- **Cilium Hubble → [Network Policy Editor](https://cilium.io/blog/2021/02/10/network-policy-editor/)** — generate NetworkPolicies from Hubble flow logs.
- **[Otterize](https://docs.otterize.com/features/network-mapping-network-policies/reference/Network-Policies-Deep-Dive)** — intent-based policies generated from an observed network map.
- **Sysdig Secure** — least-privilege NetworkPolicy generation from observed traffic.
- **Calico (Enterprise/Cloud)** — policy recommendation from flow logs.

`csd`'s wedge is being **Docker/host-oriented with `nftables` output**, where this
field assumes a cluster. (`csd` also emits `k8s-networkpolicy`, but that is one
formatter, not the product's home.)

## Adjacent, different shape: detect-and-enforce platforms

These observe behaviour and build least-privilege *enforcement*, but they are
runtime daemons/operators, not emit-and-exit generators — and `csd` puts
enforcement explicitly out of scope:

- **KubeArmor (AccuKnox)** — least-permissive inline enforcement from observed behaviour.
- **Tetragon (Cilium / Isovalent)** — observe normal behaviour → least-privilege TracingPolicies.
- **Falco**, **Tracee (Aqua)** — eBPF detection (not config generation).
- **Sysdig Secure / Aqua / Prisma Cloud / Wiz** — commercial CNAPPs with runtime least-privilege and drift recommendations.

`csd` "generates, you apply"; this tier "watches and blocks." Different jobs.

## The static alternative (and csd's own sibling)

[compose-lint](https://github.com/tmatens/compose-lint) — `csd`'s sibling — plus
**Trivy / Checkov / kube-score / Polaris / Kubescape (static)** guess hardening from
manifests. `csd`'s whole pitch is "stop guessing statically: watch it run." The
compose-lint ↔ `csd` feedback loop (derive a profile, contribute it to the static
catalog — see the [README](../README.md#relationship-to-compose-lint)) is positioning
none of the peers above replicate.

## Summary matrix

| Tool | Dynamic | eBPF | Generates config | Container-scoped | Dimensions | Deployment |
|---|---|---|---|---|---|---|
| **csd** | ✅ | ✅ | ✅ | ✅ | caps, fs, devices, privileged, cap_add, egress | one-shot CLI (Docker-first) |
| IG `advise` | ✅ | ✅ | ✅ | ✅ | seccomp, network-policy | CLI / k8s |
| Kubescape `kapprofiler` | ✅ | ✅ | profile (not hardening config) | ✅ | syscalls, caps, files, network | k8s operator |
| Security Profiles Operator | ✅ | ✅ (or audit log) | ✅ | ✅ | seccomp, apparmor, selinux | k8s operator (CRDs) |
| SlimToolkit | ✅ | ✅ | ✅ | ✅ | seccomp, apparmor (+ image minify) | CLI (Docker) |
| oci-seccomp-bpf-hook | ✅ | ✅ | ✅ | ✅ | seccomp | OCI hook (Podman) |
| Cilium/Hubble, Otterize, Sysdig (net) | ✅ | ✅ | ✅ | ✅ (k8s) | network policy | cluster |
| KubeArmor / Tetragon / Falco | ✅ | ✅ | enforcement, not config | ✅ | varies | daemon/operator |
| aa-genprof / audit2allow / udica | ✅ | ❌ (audit log) | ✅ | host/container | apparmor / selinux | host CLI |
| compose-lint / Trivy / Checkov | ❌ (static) | ❌ | ✅ (from manifest) | ✅ | varies | CI / CLI |

## Honest takeaways

- **`csd` is not "no one does this."** Runtime-derived least privilege is a
  populated category with a CNCF-adjacent incumbent (IG, which `csd` itself uses)
  and a sibling that shares its engine (Kubescape `kapprofiler`).
- **The differentiation is real but specific:** the *combination* of dimensions in
  one Docker-first CLI, the `privileged: true` decomposition framing, Compose-native
  output, the compose-lint loop, and the evidence/signing discipline.
- **The most visible gap** is that `csd` does not emit a **seccomp** profile — the
  single most common runtime-derived artifact — by design (the `security_opt` blind
  spot, [LIMITATIONS.md](LIMITATIONS.md)). A user who primarily wants seccomp should
  reach for IG `advise`, SPO, or SlimToolkit; `csd` is for the caps/devices/fs/
  `privileged`/egress dimensions those tools don't lead with.

See also: [README — Relationship to compose-lint](../README.md#relationship-to-compose-lint),
[LIMITATIONS.md](LIMITATIONS.md), [ROADMAP.md](../ROADMAP.md).
