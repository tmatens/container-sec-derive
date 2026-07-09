# container-sec-derive — convenience targets.
#
# `make ground-truth` re-bisects every reference image. Bisection takes
# minutes per image (one container restart per cap eliminated) and
# requires Docker on the host — it is not run in CI. The committed
# ground_truth.json files in testdata/<image>/ are the authoritative
# v0.1 ground truth; this target regenerates them when an image digest
# is bumped.

.PHONY: ground-truth ground-truth-postgres ground-truth-caddy ground-truth-tailscale synthetic-build smoke-wsl2 smoke-fs smoke-device smoke-capadd smoke-egress smoke-drop-seed smoke-podman apptier-immich closed-loop missrate release-prep build test vet bisect-selftest drop-test-selftest compose-derive-selftest parity image image-local verify-ig-pin ig-provenance

# IG_VERSION is extracted from internal/ig/ig.go's PinnedIGVersion so the image
# build, the runtime schema check, and the committed ig-pin/ files
# stay aligned. CSD_VERSION is git-describe with a -dev suffix when
# the working tree is dirty; the release pipeline overrides it.
IG_VERSION  := $(shell awk -F'"' '/^[[:space:]]+PinnedIGVersion[[:space:]]+=/ {print $$2; exit}' internal/ig/ig.go)
CSD_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
HOST_ARCH   := $(shell go env GOARCH)
IMAGE_REPO  := tmatens/container-sec-derive

ground-truth: ground-truth-postgres ground-truth-caddy ground-truth-tailscale

ground-truth-postgres:
	IMAGE=postgres:16 \
	IMAGE_NAME=postgres \
	WORKLOAD=$(CURDIR)/testdata/postgres/workload.sh \
	RUN_ARGS='-e POSTGRES_PASSWORD=postgres' \
	READY_TIMEOUT=60 \
	./scripts/bisect_caps.sh > testdata/postgres/ground_truth.json

ground-truth-caddy:
	IMAGE=caddy:2 \
	IMAGE_NAME=caddy \
	WORKLOAD=$(CURDIR)/testdata/caddy/workload.sh \
	RUN_ARGS='-e CADDY_ADMIN=0.0.0.0:2019 -p 127.0.0.1:18080:80 -p 127.0.0.1:12019:2019' \
	READY_TIMEOUT=30 \
	./scripts/bisect_caps.sh > testdata/caddy/ground_truth.json

ground-truth-tailscale:
	IMAGE=tailscale/tailscale:stable \
	IMAGE_NAME=tailscale \
	WORKLOAD=$(CURDIR)/testdata/tailscale/workload.sh \
	RUN_ARGS='-e TS_USERSPACE=true' \
	READY_TIMEOUT=30 \
	./scripts/bisect_caps.sh > testdata/tailscale/ground_truth.json

synthetic-build:
	docker build -t csd-synthetic-exerciser:0.1 testdata/synthetic

# WSL2 smoke matrix — see scripts/smoke_wsl2.sh and docs/wsl2.md.
# Runs csd against each reference image and reports pass/fail per
# image. Designed for WSL2 + Docker Desktop but runs anywhere with
# docker + ig + the built csd binary.
smoke-wsl2: build
	./scripts/smoke_wsl2.sh

# fs smoke matrix — see scripts/smoke_fs.sh. Runs `csd --observe fs`
# against each reference image; the synthetic exerciser is the
# deterministic hard gate (writable_paths must include the file it
# writes every cycle). Same docker + ig + privileged-host needs as
# smoke-wsl2.
smoke-fs: build
	./scripts/smoke_fs.sh

# device smoke — see scripts/smoke_device.sh. Runs `csd --observe devices`
# and `csd --observe privileged` against the synthetic exerciser run with a
# mapped non-default /dev node (`--device /dev/null:/dev/csd-exerciser-dev`):
# hardware-free, deterministic hard gates for the device classifier and the
# privileged composition's concurrent two-gadget live path.
smoke-device: build
	./scripts/smoke_device.sh

# capadd smoke — see scripts/smoke_capadd.sh. Runs `csd --observe capadd` against
# the synthetic exerciser (which deterministically fires held CHOWN/SETUID/SETGID
# checks): hardware-free, deterministic hard gates for the per-cap syscall
# correlation (CHOWN used) and the unused->removable classification (SYS_MODULE).
smoke-capadd: build
	./scripts/smoke_capadd.sh

smoke-egress: build
	./scripts/smoke_egress.sh

# smoke-drop-seed validates the pre-existing-foreign-owned-data staging fidelity
# (csd#340 item 2): a synthetic image whose entrypoint reads a foreign-owned 0600
# file derives DAC_OVERRIDE needed when seed_mounts stages that content, removable
# when the mount is fresh/empty. Docker + python + jq only (no csd build / no BPF).
smoke-drop-seed:
	./scripts/smoke_drop_seed.sh

# apptier-immich runs the app-tier verify (docs/app-tier-verification.md): brings
# up immich's released stack with the DERIVED DB hardening and drives its real API
# with a committed fixture. Live only — needs docker + the docker compose v2 plugin
# + a network pull (immich-server is ~3GB); on-demand, not a per-PR gate.
apptier-immich:
	./scripts/apptier_verify.sh testdata/apptier/immich/docker-compose.yml testdata/apptier/immich/verify.sh

# smoke-podman exercises the --runtime podman path: ig attach/attribution under
# podman + the podman inspect/history/mounts parse, via the synthetic exerciser.
# Requires podman + ig + a privileged host; see scripts/smoke_podman.sh.
smoke-podman: build
	./scripts/smoke_podman.sh

# closed-loop "meets intent" test — see scripts/closed_loop.sh. Derives a cap
# profile, RE-RUNS the workload under exactly that profile (must succeed), then
# with all caps dropped (must fail): proves the derived config is sufficient AND
# necessary. The only test that validates csd's OUTPUT, not just its pipeline.
closed-loop: build
	./scripts/closed_loop.sh

# missrate measures the kretprobe capture deficit (upper bound on the
# kretprobe miss rate) against the synthetic exerciser in counting mode.
# Requires docker + ig + a privileged host; see scripts/kretprobe_missrate.sh.
missrate: build
	./scripts/kretprobe_missrate.sh

# release-prep runs the deterministic release bumps locally for inspection
# (CHANGELOG/ToolVersion/README/goldens/test assertions + build/vet/test gate);
# it does NOT commit, push, or tag. CI runs the same script via release-prep.yml.
# Usage: make release-prep VERSION=X.Y.Z
release-prep:
	@test -n "$(VERSION)" || { echo "usage: make release-prep VERSION=X.Y.Z"; exit 2; }
	./scripts/release-prep.sh "$(VERSION)"

build:
	go build -o csd ./cmd/csd

test:
	go test ./...

vet:
	go vet ./...

# bisect-selftest validates the capability minimizer (greedy + #32 stabilization
# fixpoint, substitutability detection, verify_minimal) hermetically with
# synthetic oracles — no Docker, so it runs in the regular CI gate, unlike the
# real container-driven `make ground-truth-*`.
bisect-selftest:
	./scripts/bisect_caps_selftest.sh

# drop-test-selftest asserts drop_test.sh rejects a non-empty `fixed` (every
# granted element must be a drop-tested candidate). The guard runs before any
# docker work, so this is hermetic and belongs in the fast CI gate.
drop-test-selftest:
	./scripts/drop_test_selftest.sh

# compose-derive-selftest asserts compose_to_spec.py carries tmpfs/read_only (and
# mounts/env) into the spec, so a container's cold-start asset creation is
# exercised and its caps derive faithfully (#337). Hermetic: python+yaml, no docker.
compose-derive-selftest:
	./scripts/compose_derive_selftest.sh

# parity runs the v1 compose-lint parity cross-check gate (#294): the set
# difference between each testdata/<image>/ground_truth.json and the pinned
# curated mirror in testdata/parity/ must equal the recorded accepted_delta.
# Hermetic (no Docker/BPF/network), so it also runs inside the regular
# `make test` lane; this target is the focused local invocation.
parity:
	go test ./internal/parity/...

# verify-ig-pin re-runs cosign verification against the committed
# ig-pin/ artifacts. This is a self-consistency check (the committed
# bundle verifies against the committed pubkey) — the upstream-trust
# verification happens at pin-bump time inside scripts/refresh-ig-pin.sh
# using the freshly fetched key. Useful as a paranoia step before
# tagging a release.
verify-ig-pin:
	cosign verify-blob \
		--key ig-pin/inspektor-gadget.pub \
		--bundle ig-pin/SHA256SUMS.bundle \
		ig-pin/SHA256SUMS

# ig-provenance prints the vendored-ig provenance predicate (IG version +
# upstream per-arch digests + the cosign-verified pin) to stdout. release.yml
# attests this to the image manifest; TestIGProvenancePredicate gates it at PR
# time. Run it to eyeball what will be attested.
ig-provenance:
	@./scripts/gen-ig-provenance.sh

# image builds a local single-arch image for development. Multi-arch
# build + push lives in .github/workflows/image-build.yml; doing it
# here would require buildx + qemu setup the local dev box may not
# have. Image is tagged with the resolved CSD_VERSION so a smoke test
# can `docker run --rm <repo>:<tag> --version` and assert exact match.
image:
	docker build \
		--build-arg IG_VERSION=$(IG_VERSION) \
		--build-arg CSD_VERSION=$(CSD_VERSION) \
		--build-arg TARGETARCH=$(HOST_ARCH) \
		-t $(IMAGE_REPO):$(CSD_VERSION) \
		-t $(IMAGE_REPO):dev \
		.
