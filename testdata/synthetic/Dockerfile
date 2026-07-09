# Synthetic cap-exerciser image. Multi-stage so the final image is
# scratch + statically-linked binary; comm shows up as "exerciser"
# (no shell, no entrypoint script) which keeps Step 21's runc-comm
# filter from suppressing it.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY exerciser.c .
RUN gcc -static -O2 -Wall -o /exerciser exerciser.c

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS prep
RUN install -m 0644 /dev/null /csd-exerciser-target
# A FOREIGN-owned, mode-0600 file for the DAC_OVERRIDE read probe (#349 scenario 5,
# CSD_EXERCISE_DAC-gated). Owned by uid 65534 (nobody) with no read bit for other,
# so a root read must invoke CAP_DAC_OVERRIDE. Harmless/unread in every other smoke.
RUN printf 'csd-foreign' > /csd-exerciser-foreign \
    && chown 65534:65534 /csd-exerciser-foreign \
    && chmod 0600 /csd-exerciser-foreign

FROM scratch
COPY --from=build /exerciser /exerciser
COPY --from=prep /csd-exerciser-target /csd-exerciser-target
COPY --from=prep /csd-exerciser-foreign /csd-exerciser-foreign
ENTRYPOINT ["/exerciser"]
