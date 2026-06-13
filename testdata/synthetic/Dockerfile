# Synthetic cap-exerciser image. Multi-stage so the final image is
# scratch + statically-linked binary; comm shows up as "exerciser"
# (no shell, no entrypoint script) which keeps Step 21's runc-comm
# filter from suppressing it.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY exerciser.c .
RUN gcc -static -O2 -Wall -o /exerciser exerciser.c

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS prep
RUN install -m 0644 /dev/null /csd-exerciser-target

FROM scratch
COPY --from=build /exerciser /exerciser
COPY --from=prep /csd-exerciser-target /csd-exerciser-target
ENTRYPOINT ["/exerciser"]
