# syntax=docker/dockerfile:1.7

# Build stage
FROM rust:1.91-alpine AS builder

# Install build dependencies (disable triggers for QEMU compatibility)
RUN apk add --no-cache --no-scripts \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

ARG TARGETARCH

# Create dummy src to cache dependencies
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target,id=target-${TARGETARCH} \
    sh -c 'mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release --locked && rm -rf src target/release/deps/mikrotik* target/release/mikrotik*'

# Copy actual source code
COPY src ./src
COPY clippy.toml rustfmt.toml ./

# Build for release
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target,id=target-${TARGETARCH} \
    sh -c 'cargo build --release --locked && cp target/release/mikrotik-exporter /app/mikrotik-exporter'

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libgcc

# Create non-root user
RUN addgroup -g 1000 mikrotik && \
    adduser -D -u 1000 -G mikrotik mikrotik

WORKDIR /app

# Copy binary from builder
COPY --from=builder --chown=mikrotik:mikrotik /app/mikrotik-exporter /app/mikrotik-exporter

# Switch to non-root user
USER mikrotik

# Expose port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9090/health || exit 1

# Run the binary
ENTRYPOINT ["/app/mikrotik-exporter"]
