# Build stage
FROM rust:1.91-alpine3.19 AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy src to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src target/release/deps/mikrotik* target/release/mikrotik*

# Copy actual source code
COPY src ./src
COPY clippy.toml rustfmt.toml ./

# Build for release
RUN cargo build --release

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates libgcc

# Create non-root user
RUN addgroup -g 1000 mikrotik && \
    adduser -D -u 1000 -G mikrotik mikrotik

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/mikrotik-exporter /app/mikrotik-exporter

# Change ownership
RUN chown -R mikrotik:mikrotik /app

# Switch to non-root user
USER mikrotik

# Expose port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9090/health || exit 1

# Run the binary
ENTRYPOINT ["/app/mikrotik-exporter"]
