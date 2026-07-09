# Synthetic drop-test fidelity target (csd#340 items 2/3/4). A tiny alpine image
# whose root entrypoint probes /data in one of several ways (CSD_SEED_OP); each
# probe needs a capability only under a particular mount INITIAL STATE that the
# default fresh-empty-dir staging does not reproduce (see entrypoint.sh):
#   read  (item 2) — read a pre-existing foreign-owned 0600 file  -> DAC_OVERRIDE
#   write (item 3) — create a file in a foreign-owned restrictive dir -> DAC_OVERRIDE
#   chown (item 4) — repair ownership of a foreign-owned data dir  -> CHOWN
# Built locally by the smoke scripts; no registry counterpart.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh
# Baseline: /data owned by the service uid (1000) — the correctly-owned state, so
# the chown probe is a no-op unless the mount's initial ownership is foreign. A
# mount bound over /data shadows this (item 2/3/4 seeded/named-volume cases).
RUN mkdir -p /data && chown 1000:1000 /data
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
