#!/usr/bin/env bash
# rabbitmq correctness (capabilities): default root invocation on a fresh data
# volume. The entrypoint starts as root, `find`-chowns /var/lib/rabbitmq (no-op
# on the pre-owned volume), then re-execs as the rabbitmq user via gosu
# (SETUID/SETGID) — startup caps, invisible to runtime observation.
#
# Real function = declare -> publish -> consume over the management API: the
# plain image has no AMQP client or curl, so we enable the bundled
# rabbitmq_management plugin (what the -management tag pre-enables) and drive
# the round-trip from the curl sidecar sharing the target's netns — which also
# satisfies the default guest user's loopback-only restriction. Plus the
# non-root uid assert on beam.smp (the redis/mariadb sharp edge).
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"
. "$(dirname "$0")/lib/sidecar.sh"

# SHARP EDGE 2: exec the rabbitmq CLIs AS THE rabbitmq USER (--user rabbitmq),
# never as root. An exec'd process runs inside the target's bounding cap set,
# so a root-run probe's own needs pollute the derived minimum: root needs
# DAC_OVERRIDE to read the rabbitmq-owned 0600 .erlang.cookie and FOWNER to
# rewrite the rabbitmq-owned enabled_plugins — both derived falsely-required
# on the first run of this spec, while the broker itself was healthy.
#
# SHARP EDGE 1: do NOT exec any rabbitmq CLI into the container during boot. An
# exec'd root-run Erlang client races the entrypoint for the creation of
# /var/lib/rabbitmq/.erlang.cookie — if root wins, the broker (running as the
# rabbitmq user) cannot read its own cookie and beam crashes (erl_crash.dump).
# Reproduced deterministically on rabbitmq:4.3. Gate on the broker's own
# "Server startup complete" log line first — reading docker logs touches
# nothing inside the container.
deadline=$((SECONDS+90))
until grep -q "Server startup complete" <<<"$(docker logs "$C" 2>&1)"; do
  (( SECONDS >= deadline )) && { echo "rabbitmq never reached startup complete"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done
docker exec --user rabbitmq "$C" rabbitmq-diagnostics -q ping >/dev/null 2>&1 || { echo "ping failed after startup"; exit 1; }

docker exec --user rabbitmq "$C" rabbitmq-plugins enable --online rabbitmq_management >/dev/null 2>&1 \
  || { echo "could not enable rabbitmq_management"; exit 1; }
deadline=$((SECONDS+30))
until sidecar_curl -sf -u guest:guest --max-time 5 http://localhost:15672/api/overview >/dev/null 2>&1; do
  (( SECONDS >= deadline )) && { echo "management API never came up"; exit 1; }
  sleep 1
done

# declare -> publish -> get round-trip on the default vhost.
sidecar_curl -sf -u guest:guest --max-time 10 -X PUT \
  -H 'content-type: application/json' -d '{"durable":true}' \
  http://localhost:15672/api/queues/%2F/csd-probe >/dev/null \
  || { echo "queue declare failed"; exit 1; }
routed="$(sidecar_curl -s -u guest:guest --max-time 10 -X POST \
  -H 'content-type: application/json' \
  -d '{"properties":{},"routing_key":"csd-probe","payload":"csd-42","payload_encoding":"string"}' \
  http://localhost:15672/api/exchanges/%2F/amq.default/publish)"
case "$routed" in *'"routed":true'*) ;; *) echo "publish not routed (got: ${routed:0:80})"; exit 1;; esac
got="$(sidecar_curl -s -u guest:guest --max-time 10 -X POST \
  -H 'content-type: application/json' \
  -d '{"count":1,"ackmode":"ack_requeue_false","encoding":"auto"}' \
  http://localhost:15672/api/queues/%2F/csd-probe/get)"
case "$got" in *'"payload":"csd-42"'*) ;; *) echo "consume failed (got: ${got:0:80})"; exit 1;; esac

# Broker dropped to a non-root uid (the gosu root->rabbitmq drop).
uid="$(docker exec "$C" sh -c 'for p in /proc/[0-9]*; do a0=$(tr "\0" "\n" <"$p/cmdline" 2>/dev/null | head -1); case "$a0" in *beam.smp) awk "/^Uid:/{print \$2}" "$p/status"; break;; esac; done')"
[ -n "$uid" ] && [ "$uid" != 0 ] || { echo "beam.smp running as ROOT or not found (gosu drop failed): uid=${uid:-none}"; exit 1; }

echo "correct: publish/consume round-trip ok, beam.smp uid=$uid (non-root)"
