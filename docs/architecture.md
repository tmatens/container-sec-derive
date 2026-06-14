# Architecture diagram

Visual companion to [`PLAN.md` §Architecture](../PLAN.md#architecture). The plan is authoritative; this page is a map.

## Layered pipeline

`csd observe` is a four-layer pipeline. `csd verify` is a fifth layer that re-runs the pipeline against a proposed config.

```mermaid
flowchart TB
    subgraph Host["Host (CAP_BPF + CAP_PERFMON, --pid=host)"]
        kernel[["Linux kernel<br/>cap_capable LSM hook"]]
        runtime[["Container runtime<br/>(docker.sock + /events)"]]
    end

    subgraph IG["ig subprocess (pinned upstream SHA)"]
        gadget["trace_capabilities gadget"]
    end

    subgraph CSD["csd"]
        direction TB
        observer["1. Observer<br/>cap_capable<br/>(NDJSON parser)"]
        attribution["2. Container attribution<br/>(cgroup_id, pid) → (container_id, image, digest)"]
        aggregator["3. Aggregator<br/>distinct caps per image<br/>+ counts + timing"]
        formatter["4. Formatter<br/>compose / compose-patch / docker-run /<br/>oci / k8s / json / compose-lint-profile"]
        sidecar[("Evidence sidecar<br/>schema_version 1.x")]
        validator["5. Validator (csd verify)<br/>re-run with proposed config"]
    end

    user(["User / CI"])
    artifact[/"Policy artifact<br/>(stdout)"/]
    verifyResult[/"Verify result<br/>(consistent / insufficient / over_permissioned)"/]

    kernel -->|BPF events| gadget
    runtime -->|container events| attribution
    gadget -->|NDJSON| observer
    observer --> attribution
    attribution --> aggregator
    aggregator --> formatter
    aggregator --> sidecar
    formatter --> artifact
    sidecar -.->|verify_of| validator
    validator --> verifyResult
    user -->|csd observe| CSD
    user -->|csd verify| validator
```

**Why the layering matters.** v1 ships exactly one observer (`cap_capable`). v0.2+ adds siblings (`writable_path`, `device_open`, `socket_connect`, …) that plug into the same attribution + aggregator + formatter chain. Collapsing the layers to ship faster trades v0.2 for v0.1 weeks — it is load-bearing.

## Three-phase workflow

Borrowed from AppArmor's complain → enforce pattern.

```mermaid
flowchart LR
    record["1. Record<br/>run with no cap_drop<br/>observe everything"]
    suggest["2. Suggest<br/>emit policy + sidecar<br/>(optional interactive)"]
    verify["3. Verify<br/>re-run with proposed config<br/>same workload, watch for new denials"]

    record --> suggest --> verify
    verify -.->|insufficient: missing cap| record
    verify -.->|over-permissioned: trim| suggest
```

Phases 1 and 2 ship in `csd observe`. Phase 3 is `csd verify`, a self-consistency check — not a sufficiency proof. Workload coverage is the ceiling on both.

## Workload-coverage cross-checks

Three signals run alongside observation to convert silent coverage gaps into loud warnings.

```mermaid
flowchart TB
    obs["Observed caps<br/>(from cap_capable)"]
    entry["Entrypoint cross-check<br/>(docker inspect + script scan)"]
    steady["Steady-state detector<br/>no new cap in final max(60s, 25%)"]
    profile["compose-lint curated profile<br/>(reference images only)"]

    rubric{{"Confidence rubric<br/>high / moderate / low"}}
    warnings[/"coverage_warnings[]<br/>in sidecar"/]

    obs --> rubric
    entry -->|expected ⊄ observed| warnings
    entry --> rubric
    steady --> rubric
    profile -->|reference-image runs| rubric
    warnings --> rubric
```

Confidence rubric definition lives in [`PLAN.md` §Confidence scoring](../PLAN.md#confidence-scoring) — this diagram only shows the inputs.

## Privilege & supply-chain posture

Every layer in the pipeline runs under the same blast radius.

```mermaid
flowchart LR
    subgraph Trust["Trust boundary: root-equivalent on host"]
        csd["csd binary<br/>(cosign-signed,<br/>SBOM per release)"]
        ig["vendored ig binary<br/>(pinned upstream SHA,<br/>cosign-verified at pin time)"]
    end
    sock[("/var/run/docker.sock")]
    pidns[("--pid=host")]
    bpf[("CAP_BPF + CAP_PERFMON")]

    csd --- sock
    csd --- pidns
    ig --- bpf
    csd --> ig
```

See [`PLAN.md` §Tool posture](../PLAN.md#tool-posture) for the full threat model and [`PLAN.md` §Supply-chain](../PLAN.md#supply-chain) for the release path.
