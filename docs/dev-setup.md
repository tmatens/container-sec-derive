# Local dev setup

What you need to develop and exercise `csd` end-to-end on a Linux host.

## Prerequisites

- **Go** 1.22 or newer.
- **Docker** (or another OCI runtime reachable via the docker socket). Used by the bisection driver and as the runtime `csd observe` attaches to.
- **Linux kernel** 5.10+ with BPF + perf enabled. eBPF gadgets need `CAP_BPF` + `CAP_PERFMON` (root works; unprivileged setups must grant both).
- **Inspektor Gadget (`ig`)** at the version pinned in `main.go`. See below.

The bisection driver (`scripts/bisect_caps.sh`) only needs Go, bash, and Docker — it does not need `ig`. `ig` is required for `csd observe` and any test path that exercises the live BPF observer (anything beyond `--fixture`).

## Installing `ig`

`csd` pins to a specific `ig` release; the constants in `main.go` are the source of truth:

```
PinnedIGVersion    = "v0.51.0"
MinIGVersion       = "v0.51.0"
MaxTestedIGVersion = "v0.51.0"
```

Running against any other version triggers a stderr warning at startup; running against a version whose schema diverges produces zero parsed events. Match the pinned version exactly when developing.

### Linux (amd64 / arm64)

Pick the matching tarball from the release assets and install to `/usr/local/bin`:

```sh
IG_VERSION=v0.51.0
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -sSL -o /tmp/ig.tar.gz \
  "https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/ig-linux-${ARCH}-${IG_VERSION}.tar.gz"
sudo tar -C /usr/local/bin -xzf /tmp/ig.tar.gz ig
ig version
```

`ig version` should report `v0.51.0`. If you get a different version, `csd observe` will warn and may produce empty output.

### Verifying the install

```sh
sudo ig version
sudo ig run trace_capabilities:v0.51.0 --help >/dev/null
```

The second command pulls the gadget OCI image (also pinned to `v0.51.0`) and validates that the runtime can execute it. The first run is slow because of the image pull.

## Smoke-running `csd observe`

After `ig` is installed, you can run the live observer against any container:

```sh
go build -o csd .
sudo ./csd observe --container <name-or-id> --duration 30s
```

Add `--out sidecar.json` to capture the canonical evidence sidecar.

For the reference images, use the workloads under `testdata/<image>/` to drive the container while `csd observe` is recording. The bisected ground-truth files (`testdata/<image>/ground_truth.json`) are what observe-vs-truth runs compare against.

## Bisecting a new reference image

The bisection driver only needs Docker:

```sh
make ground-truth-postgres   # or ground-truth-caddy, ground-truth-tailscale
make ground-truth            # all three
```

Each target writes `testdata/<image>/ground_truth.json`. Each run takes several minutes — one container restart per Docker default capability.

## When `ig` is not available

You can do most local development without `ig`:

- All `go test ./...` passes; tests use `--fixture` paths and committed NDJSON under `testdata/`.
- The bisection driver runs.
- `csd observe --fixture <ndjson>` exercises the observe path without BPF.

What you cannot do without `ig`:

- Validate that observe-vs-bisection comparisons close the v1 Correctness criterion item 1.
- Reproduce the live numbers in PLAN.md §v0.1 build order item 3 (the `init_window_suppressed = 299` etc. counts).
- Smoke-test ig version compatibility against a real ig binary.
