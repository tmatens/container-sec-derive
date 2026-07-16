#!/usr/bin/env bash
# minio correctness (capabilities): default single-node invocation. Real
# function = an S3 make-bucket + put + get round-trip via the pinned `mc`
# client run as a sidecar in the target's netns (the server image ships no
# client). MC_HOST_ env alias keeps mc config-free; the only writes are the
# object store's own. minio serves as root with no drop (jellyfin-class) —
# the round-trip is the pass signal. Capture-then-match throughout.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

# minio/mc RELEASE-pinned by digest (test-only probe image, multi-arch).
MC_IMAGE="${CSD_PROBE_MC_IMAGE:-minio/mc@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727}"
mcx() { docker run --rm --entrypoint /bin/sh --network "container:${C}" \
        -e MC_HOST_csd=http://csdadmin:CsdProbe-Pw-12345@localhost:9000 "$MC_IMAGE" -c "$*"; }

deadline=$((SECONDS+45))
until mcx 'mc ls csd/ >/dev/null 2>&1'; do
  (( SECONDS >= deadline )) && { echo "minio never answered mc ls: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done

got="$(mcx 'mc mb -p csd/csdbucket >/dev/null 2>&1; echo csd-payload-42 | mc pipe csd/csdbucket/probe.txt >/dev/null 2>&1 && mc cat csd/csdbucket/probe.txt 2>/dev/null')"
[ "$got" = "csd-payload-42" ] || { echo "S3 round-trip failed (got: ${got:0:60})"; exit 1; }

echo "correct: S3 mb/put/get round-trip ok"
