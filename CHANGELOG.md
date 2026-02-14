# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- DHCP metrics support (in development for v0.3.0)
- Route metrics support (in development for v0.3.0)
- Firewall metrics support (in development for v0.3.0)
- Neighbors metrics support (in development for v0.3.0)
- POE metrics support (in development for v0.3.0)

## [0.2.2] - 2026-02-15

### Fixed
- Multi-arch Docker manifest publishing in CI
- Connection pool initialization and cleanup edge cases
- Metric initialization (counters now start at 0 instead of NaN or missing)

### Changed
- Refactored internal module structure for better maintainability
- Improved documentation and configuration examples

## [0.2.1] - 2026-02-11

### Changed
- CI: Add path filtering to GitHub Actions workflows for faster builds

## [0.2.0] - 2026-02-11

### Added
- WireGuard monitoring support with peer rx/tx bytes and latest handshake metrics
- Open connections stats panel with IPv4/IPv6 support

### Fixed
- Stale system_info gauge issue where old labels were not properly reset
- Conntrack metrics isolation for multi-router configurations
- AtomicUsize underflow race condition in connection pool
- Proper WireGuard handshake timestamp parsing with support for RouterOS duration format

### Changed
- Improved Grafana dashboard with better visualizations and metadata
- Refactored WireGuard peer identification to use allowed-address instead of public-key for enhanced privacy
- Updated documentation to reflect current project status and capabilities

### Removed
- Unused zeroize dependency to reduce binary size

## [0.1.1] - 2026-02-09

### Fixed
- Health check endpoint now properly returns 503 when routers have errors
- Connection pool backoff algorithm improvements for better reliability
- RouterOS authentication method selection to support both legacy and modern versions

## [0.1.0] - 2025-11-15

### Added
- Initial release of the Prometheus exporter for MikroTik RouterOS devices
- Interface metrics including rx/tx bytes, packets, and errors
- System resource metrics such as CPU load, memory usage, and uptime
- Connection tracking metrics with IPv4/IPv6 support
- HTTP `/metrics` endpoint for Prometheus scraping
- HTTP `/health` endpoint for service health monitoring
- Environment variable based configuration
- Connection pooling with exponential backoff for efficient resource usage
- Multi-router support with unique naming requirements