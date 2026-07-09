#!/usr/bin/env bash
# Adversarial capadd smoke (#349 scenario 5): csd must NOT narrow a capability it
# cannot soundly narrow. DAC_OVERRIDE and the finer DAC_READ_SEARCH differ by
# read-only vs read-write intent, but the cap_capable check fires at openat(),
# whose syscall NAME cannot reveal O_RDONLY vs O_RDWR — so a DAC_OVERRIDE observed
# only via openat could still have been a write, and csd must keep DAC_OVERRIDE
# rather than suggest the read-only DAC_READ_SEARCH (which would break a write path).
#
# This is the conservative-correctness guard-rail complementary to scenario 6's
# SOUND SYS_ADMIN->PERFMON substitution: csd narrows when the syscall proves it and
# refuses when it can't. A future KB edit that mapped openat->DAC_READ_SEARCH would
# be unsound and this smoke would fail loudly.
#
# The synthetic exerciser (CSD_EXERCISE_DAC=1) reads a foreign-owned mode-0600 file
# as root every cycle — a read that needs CAP_DAC_OVERRIDE (root is not the owner).
# We grant DAC_OVERRIDE and validate it: the finding must be used=true with an
# EMPTY finer_caps (not narrowed) and advice that does not offer DAC_READ_SEARCH as
# a substitute.
#
# Requires: docker, csd (built; pass CSD=/path), jq, the pinned ig on PATH.
#   make smoke-adversarial-dac   |   ./scripts/smoke_adversarial_dac.sh
set -uo pipefail

CSD="${CSD:-./csd}"
DURATION="${DURATION:-30s}"
IMAGE="csd-synthetic-exerciser:0.1"
CAP_ADD="DAC_OVERRIDE"
CONTAINER="csd-adv-dac-smoke"

[[ -x "${CSD}" ]] || { echo "smoke-adversarial-dac: csd not found/executable at ${CSD}" >&2; exit 2; }
command -v jq     >/dev/null 2>&1 || { echo "smoke-adversarial-dac: jq required" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "smoke-adversarial-dac: docker required" >&2; exit 2; }

# ALWAYS rebuild — do NOT skip-if-exists. The shared csd-synthetic-exerciser:0.1
# tag persists across jobs on a non-ephemeral self-hosted runner, so a skip-if-
# exists guard (as the other smokes use) would run this test against a STALE image
# lacking the CSD_EXERCISE_DAC read probe — which is exactly the false-0-events
# failure this smoke first hit. The exerciser source is what changed, so rebuild it.
echo "smoke-adversarial-dac: (re)building synthetic exerciser image from current source"
docker build -t "${IMAGE}" testdata/synthetic >/dev/null || { echo "FAIL: image build" >&2; exit 1; }

WORKDIR="$(mktemp -d)"; trap 'rm -rf "${WORKDIR}"' EXIT
WORKLOAD="$(pwd)/testdata/synthetic/workload.sh"
SIDECAR="${WORKDIR}/dac.json"; LOG="${WORKDIR}/dac-csd.log"

docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
# Docker's default cap set already includes DAC_OVERRIDE (so the root read of the
# foreign file succeeds and fires capable=true); CSD_EXERCISE_DAC=1 turns on the
# read probe (off for every other smoke).
if ! docker run -d --name "${CONTAINER}" -e CSD_EXERCISE_DAC=1 "${IMAGE}" >/dev/null; then
    echo "FAIL adversarial-dac: docker run failed"; exit 1
fi

(CONTAINER="${CONTAINER}" "${WORKLOAD}" >"${WORKDIR}/workload.log" 2>&1 || true) &
WPID=$!
rc=0
"${CSD}" --observe capadd --cap-add "${CAP_ADD}" --container "${CONTAINER}" \
    --duration "${DURATION}" --workload "${WORKLOAD}" --out "${SIDECAR}" >"${LOG}" 2>&1 && rc=0 || rc=$?
wait "${WPID}" 2>/dev/null || true
docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
if [[ ${rc} -ne 0 ]]; then
    case ${rc} in
        30) echo "FAIL adversarial-dac: SchemaMismatch (30) — host ig != PinnedIGVersion" ;;
        31) echo "FAIL adversarial-dac: IGMissing (31) — install the pinned ig" ;;
        *)  echo "FAIL adversarial-dac: csd exited ${rc}; see ${LOG}" ;;
    esac
    exit 1
fi
[[ -s "${SIDECAR}" ]] || { echo "FAIL adversarial-dac: sidecar empty at ${SIDECAR}"; exit 1; }

# The DAC_OVERRIDE finding must be USED (the read fired the check) and NOT narrowed:
# finer_caps empty AND advice does not offer DAC_READ_SEARCH.
USED_GATE='(.capadd_validation.findings // []) | any(.cap == "DAC_OVERRIDE" and .used == true)'
NOFINER_GATE='(.capadd_validation.findings // []) | any(.cap == "DAC_OVERRIDE" and ((.finer_caps // []) | length == 0))'
if ! jq -e "${USED_GATE}" "${SIDECAR}" >/dev/null; then
    echo "FAIL adversarial-dac: DAC_OVERRIDE not observed used (read probe didn't fire?); got $(jq -c '.capadd_validation.findings' "${SIDECAR}")"
    exit 1
fi
if ! jq -e "${NOFINER_GATE}" "${SIDECAR}" >/dev/null; then
    echo "FAIL adversarial-dac: csd WRONGLY narrowed DAC_OVERRIDE (non-empty finer_caps) — unsound (openat can't prove read-only)"
    echo "  finding: $(jq -c '.capadd_validation.findings[] | select(.cap==\"DAC_OVERRIDE\")' "${SIDECAR}")"
    exit 1
fi
if jq -e '(.capadd_validation.findings // []) | any(.cap=="DAC_OVERRIDE" and (.advice | test("DAC_READ_SEARCH")))' "${SIDECAR}" >/dev/null; then
    echo "FAIL adversarial-dac: advice offers DAC_READ_SEARCH as a substitute — unsound narrowing"
    exit 1
fi

sys="$(jq -rc '(.capadd_validation.findings[] | select(.cap=="DAC_OVERRIDE") | [.syscalls[].name]) // []' "${SIDECAR}")"
echo "PASS adversarial-dac: DAC_OVERRIDE used (syscalls=${sys}) and NOT narrowed (finer_caps empty) — csd stays conservative under ambiguous read/write signal"
echo "smoke-adversarial-dac: 1 passed, 0 failed"
