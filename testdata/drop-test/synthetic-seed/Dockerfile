# Synthetic drop-test fidelity target (csd#340 item 2). A tiny alpine image whose
# entrypoint reads a file on /data: if that file is a pre-existing, foreign-owned
# mode-0600 file, reading it AS ROOT requires CAP_DAC_OVERRIDE; if the mount is a
# fresh empty dir, nothing requires it. Same image, two mount states — the pair
# proves the fresh-only staging bias (a cap exercised only against pre-existing
# foreign-owned content is invisible when the drop-test stages a fresh empty dir).
# Built locally by scripts/smoke_drop_seed.sh; no registry counterpart.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
