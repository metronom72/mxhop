FROM rust:1.99-alpine3.22 AS builder

RUN apk add --no-cache musl-dev build-base

WORKDIR /src
COPY . .

RUN rustup target add x86_64-unknown-linux-musl \
    && cargo build --locked --release --target x86_64-unknown-linux-musl \
    && strip target/x86_64-unknown-linux-musl/release/mxhop

FROM alpine:3.22

RUN addgroup -g 10001 -S mxhop && adduser -u 10001 -S -G mxhop mxhop

COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/mxhop /usr/local/bin/mxhop
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

EXPOSE 2525

VOLUME ["/var/lib/mxhop/spool"]

USER 10001:10001

ENV MXHOP_CONFIG=/etc/mxhop/mxhop.toml

HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD printf 'QUIT\r\n' | nc -w 5 127.0.0.1 2525 | grep -q '^220 '

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["run"]
