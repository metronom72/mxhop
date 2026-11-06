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
#
# rust-toolchain.toml is kept OUT of the build context (see .dockerignore).
# With it present cargo resolves `stable`, which is not what this image
# installs, so rustup would download the day's stable plus rustfmt and clippy
# on every build — making the image depend on the network and on whatever
# `stable` means today, and the 1.91 tag above purely cosmetic. Excluded, the
# build uses the toolchain the base image pins. It is not set as
# RUSTUP_TOOLCHAIN here because that would have to name an exact patch
# version, which the 1.91 tag bumps underneath us.
#
# --locked: build the dependency versions Cargo.lock records, so the released
# image contains what CI tested rather than whatever resolved today.
RUN rustup target add x86_64-unknown-linux-musl \
    && cargo build --locked --release --target x86_64-unknown-linux-musl \
    && strip target/x86_64-unknown-linux-musl/release/mxhop

# Alpine rather than scratch because the entrypoint is a shell script and
# the healthcheck needs busybox nc and grep; everything else is the single
# binary.
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

# An SMTP banner on the loopback. This is deliberately NOT `mxhop check`:
# check rereads the certificate and key, while the running process keeps
# serving the certificate it already loaded when a reload fails — by design.
# So a renewal that leaves the key unreadable to uid 10001 would have failed
# three probes, had the task killed, and then restart-looped on the
# entrypoint's own check, closing port 25 for as long as nobody was awake,
# instead of serving the still-valid old certificate for weeks.
#
# What this proves: the listener is up and completes a TCP accept with a 220
# greeting. What it does not prove: that TLS, the spool or delivery work, or
# that the port is reachable from outside the container. It fails exactly in
# the case where a restart is the right answer — a process that is alive but
# no longer accepting — which `check` never noticed.
#
# Port 2525 is hard-coded because the image's own documentation requires
# listen = "0.0.0.0:2525"; nc and printf are busybox, already in the image.
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD printf 'QUIT\r\n' | nc -w 5 127.0.0.1 2525 | grep -q '^220 '

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["run"]
