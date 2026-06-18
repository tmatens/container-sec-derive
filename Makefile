# container-sec-derive — convenience targets.
#
# `make ground-truth` re-bisects every reference image. Bisection takes
# minutes per image (one container restart per cap eliminated) and
# requires Docker on the host — it is not run in CI. The committed
# ground_truth.json files in testdata/<image>/ are the authoritative
# v0.1 ground truth; this target regenerates them when an image digest
# is bumped.

.PHONY: ground-truth ground-truth-postgres ground-truth-caddy ground-truth-tailscale synthetic-build smoke-wsl2 smoke-fs smoke-device smoke-capadd smoke-egress closed-loop missrate build test vet image image-local verify-ig-pin ig-provenance

# IG_VERSION is extracted from main.go's PinnedIGVersion so the image
# build, the runtime schema check, and the committed ig-pin/ files
# stay aligned. CSD_VERSION is git-describe with a -dev suffix when
# the working tree is dirty; the release pipeline overrides it.
IG_VERSION  := $(shell awk -F'"' '/^[[:space:]]+PinnedIGVersion[[:space:]]+=/ {print $$2; exit}' main.go)
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

build:
	go build -o csd .

test:
	go test ./...

vet:
	go vet ./...

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
