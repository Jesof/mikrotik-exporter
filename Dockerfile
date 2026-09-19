# syntax=docker/dockerfile:1.22.0@sha256:4a43a54dd1fedceb30ba47e76cfcf2b47304f4161c0caeac2db1c61804ea3c91

FROM rust:1.98.0-alpine3.24@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo ./.cargo
COPY src ./src
COPY benches ./benches
ARG TARGETARCH
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,id=target-1.98.0-${TARGETARCH},sharing=locked \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) exit 1 ;; \
    esac && \
    cargo build --release --all-features --locked --bin mikrotik-exporter --target "$target" && \
    cp "target/$target/release/mikrotik-exporter" /app/mikrotik-exporter

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
LABEL org.opencontainers.image.title="MikroTik Exporter" \
      org.opencontainers.image.description="Prometheus exporter for MikroTik RouterOS devices" \
      org.opencontainers.image.source="https://github.com/Jesof/mikrotik-exporter" \
      org.opencontainers.image.licenses="MIT"
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates libgcc && \
    addgroup -g 1000 mikrotik && \
    adduser -D -u 1000 -G mikrotik mikrotik
WORKDIR /app
COPY --from=builder --chown=1000:1000 /app/mikrotik-exporter /app/mikrotik-exporter
USER 1000:1000
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:9090/live || exit 1
ENTRYPOINT ["/app/mikrotik-exporter"]
