FROM rust:1.99-alpine3.22 AS builder

RUN apk add --no-cache musl-dev build-base ca-certificates

WORKDIR /src
COPY . .

RUN cargo build --locked --release \
    && strip target/release/mxhop \
    && cp target/release/mxhop /mxhop \
    && ! readelf -d /mxhop | grep -q NEEDED \
    && printf 'mxhop:x:10001:10001::/nonexistent:/sbin/nologin\n' > /passwd.mxhop \
    && printf 'mxhop:x:10001:\n' > /group.mxhop \
    && mkdir -p /spool

FROM scratch

COPY --from=builder /passwd.mxhop /etc/passwd
COPY --from=builder /group.mxhop /etc/group
COPY --from=builder --chown=10001:10001 /spool /var/lib/mxhop/spool
COPY --from=builder /mxhop /mxhop

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

EXPOSE 2525

VOLUME ["/var/lib/mxhop/spool"]

USER 10001:10001

ENV MXHOP_CONFIG=/etc/mxhop/mxhop.toml

HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/mxhop", "health"]

ENTRYPOINT ["/mxhop"]
CMD ["run"]
