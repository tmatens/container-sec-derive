# Synthetic cap-exerciser image. Multi-stage so the final image is
# scratch + statically-linked binary; comm shows up as "exerciser"
# (no shell, no entrypoint script) which keeps Step 21's runc-comm
# filter from suppressing it.
FROM alpine:3.20 AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY exerciser.c .
RUN gcc -static -O2 -Wall -o /exerciser exerciser.c

FROM alpine:3.20 AS prep
RUN install -m 0644 /dev/null /csd-exerciser-target

FROM scratch
COPY --from=build /exerciser /exerciser
COPY --from=prep /csd-exerciser-target /csd-exerciser-target
ENTRYPOINT ["/exerciser"]
