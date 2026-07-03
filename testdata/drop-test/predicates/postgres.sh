#!/usr/bin/env bash
# Correct iff the postgres reference workload completes under the container's
# config. If postgres can't start (e.g. read_only with no socket tmpfs), the
# workload's pg_isready poll times out and this fails.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"
PGCONTAINER="$DROP_TEST_CONTAINER" bash "$(cd "$(dirname "$0")/../../.." && pwd)/testdata/postgres/workload.sh"
