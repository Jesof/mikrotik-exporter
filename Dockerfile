# syntax=docker/dockerfile:1.22.0@sha256:4a43a54dd1fedceb30ba47e76cfcf2b47304f4161c0caeac2db1c61804ea3c91

FROM rust:1.99.1-alpine3.24@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo ./.cargo
COPY src ./src
COPY benches ./benches
ARG TARGETARCH
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,id=target-1.99.0-${TARGETARCH},sharing=locked \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) exit 1 ;; \
    esac && \
    cargo build --release --all-features --locked --bin mikrotik-exporter --target "$target" && \
    cp "target/$target/release/mikrotik-exporter" /app/mikrotik-exporter

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
LABEL org.opencontainers.image.title="MikroTik Exporter" \
      org.opencontainers.image.description="Prometheus exporter for MikroTik RouterOS devices" \
      org.opencontainers.image.source="https://github.com/Jesof/mikrotik-exporter" \
      org.opencontainers.image.licenses="MIT"
# Runtime packages are pinned to exact versions for reproducible builds; the
# libcrypto3/libssl3 bumps carry the OpenSSL CVE-2026-14456 fix. Do not replace
# the pins with an unpinned `apk upgrade`: that defeats the base digest pin.
RUN apk add --no-cache \
      ca-certificates=20261020-r0 \
      libgcc=15.2.0-r5 \
      libcrypto3=3.5.9-r0 \
      libssl3=3.5.9-r0 && \
    addgroup -g 1000 mikrotik && \
    adduser -D -u 1000 -G mikrotik mikrotik
WORKDIR /app
COPY --from=builder --chown=1000:1000 /app/mikrotik-exporter /app/mikrotik-exporter
USER 1000:1000
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:9090/live || exit 1
ENTRYPOINT ["/app/mikrotik-exporter"]
