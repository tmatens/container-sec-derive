# container-sec-derive — convenience targets.
#
# `make ground-truth` re-bisects every reference image. Bisection takes
# minutes per image (one container restart per cap eliminated) and
# requires Docker on the host — it is not run in CI. The committed
# ground_truth.json files in testdata/<image>/ are the authoritative
# v0.1 ground truth; this target regenerates them when an image digest
# is bumped.

.PHONY: ground-truth ground-truth-postgres ground-truth-caddy ground-truth-tailscale build test vet

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
	RUN_ARGS='-p 127.0.0.1:18080:80' \
	READY_TIMEOUT=30 \
	./scripts/bisect_caps.sh > testdata/caddy/ground_truth.json

ground-truth-tailscale:
	IMAGE=tailscale/tailscale:stable \
	IMAGE_NAME=tailscale \
	WORKLOAD=$(CURDIR)/testdata/tailscale/workload.sh \
	RUN_ARGS='-e TS_USERSPACE=true' \
	READY_TIMEOUT=30 \
	./scripts/bisect_caps.sh > testdata/tailscale/ground_truth.json

build:
	go build -o csd .

test:
	go test ./...

vet:
	go vet ./...
