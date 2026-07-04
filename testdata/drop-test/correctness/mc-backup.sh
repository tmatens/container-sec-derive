#!/usr/bin/env bash
# mc-backup (itzg/mc-backup) correctness (capabilities), IN-STACK. mc-backup is a
# DEPENDENT tier: it RCON-connects to the minecraft server (the `deps:` entry) to
# flush the world (save-off/save-on), then tars the SHARED /data volume into
# /backups. Correctness = a REAL backup is produced — the newest archive must
# CONTAIN the world (many entries), not merely exist.
#
# Why the content check matters: mc-backup runs as root and can always create the
# archive FILE, but reading minecraft's uid-1000, mode-0750 /data as root needs
# DAC_OVERRIDE. Without it, tar silently archives nothing and produces a 0-entry
# empty tarball that still "exists" — a weak "file present" check would pass on a
# broken backup (this is precisely how a real deployment can ship empty backups).
# Counting entries is what actually gates the read capability.
set -uo pipefail
: "${DROP_TEST_CONTAINER:?}"; C="$DROP_TEST_CONTAINER"

backup_entries() {
  local f; f="$(docker exec "$C" sh -c 'ls -t /backups/*.tgz /backups/*.tar.gz /backups/*.tar 2>/dev/null | head -1' 2>/dev/null)"
  [ -n "$f" ] || { echo 0; return; }
  docker exec "$C" sh -c "tar tzf '$f' 2>/dev/null | wc -l" 2>/dev/null | tr -dc 0-9
}

deadline=$((SECONDS+90))
while :; do
  n="$(backup_entries)"; n="${n:-0}"
  [ "$n" -ge 5 ] && { echo "correct: backup archive contains the world ($n entries)"; exit 0; }
  (( SECONDS >= deadline )) && { echo "no real backup: newest archive has ${n} entries (empty tar -> mc-backup could not read the shared /data)"; exit 1; }
  [ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" = true ] || { echo "container exited: $(docker logs "$C" 2>&1 | tail -1)"; exit 1; }
  sleep 2
done
