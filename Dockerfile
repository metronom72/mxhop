# syntax=docker/dockerfile:1

# Two stages: a builder that has a C toolchain (ring compiles C for the
# target, so musl-dev and build-base are not optional), and a final stage
# that has nothing but the one static binary. CI already proves this target
# links, so the image is not the first place it is tried.
FROM rust:1.91-alpine AS builder

RUN apk add --no-cache musl-dev build-base

WORKDIR /src
COPY . .

# Fully static: the final stage shares no libc with the builder, so a
# dynamically linked binary would not start there.
RUN rustup target add x86_64-unknown-linux-musl \
    && cargo build --release --target x86_64-unknown-linux-musl \
    && strip target/x86_64-unknown-linux-musl/release/mxhop

# Alpine rather than scratch only because the entrypoint has to run two
# commands in order and a healthcheck needs something to exec; everything
# else is the single binary.
FROM alpine:3.22

# A fixed uid, so a bind-mounted spool on the host can be chowned to a number
# the operator can write down and that survives an image rebuild.
RUN addgroup -g 10001 -S mxhop && adduser -u 10001 -S -G mxhop mxhop

COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/mxhop /usr/local/bin/mxhop
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# The container listens on 2525, not 25. Port 25 is privileged, so binding it
# inside the container would mean either running as root or granting
# CAP_NET_BIND_SERVICE; publishing 25 on the host side and forwarding to 2525
# costs neither, which is what lets the deployment keep `cap_drop: ALL`.
# The config file must agree: listen = "0.0.0.0:2525".
EXPOSE 2525

# The spool holds mail that has been accepted but not delivered. Declaring it
# a volume means a plain `docker run` cannot silently write it into the
# container's writable layer, where `docker rm` would take undelivered mail
# with it. In Swarm the stack file binds a host path over this path; the
# declaration is the backstop for every other way of starting the image.
VOLUME ["/var/lib/mxhop/spool"]

USER 10001:10001

ENV MXHOP_CONFIG=/etc/mxhop/mxhop.toml

# `check` can answer today and answers quickly: it parses the config and
# reads the TLS files. It does NOT prove the listener is accepting mail —
# there is no health endpoint in the binary yet, so claiming more would be a
# lie. It still catches the case this is here for: a config or certificate
# the running process can no longer read.
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/mxhop", "check"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["run"]
