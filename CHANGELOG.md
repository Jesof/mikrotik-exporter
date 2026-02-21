# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added
- English translation of README for international users
- Renamed counter metrics to use `_total` suffix following Prometheus naming conventions

### Changed
- Counter metrics (interface rx/tx bytes/packets/errors, firewall bytes/packets) now start with current router values on exporter startup instead of zero
- CI optimizations with smart path filtering and tool caching for faster builds
- CI now uses tags instead of SHA for GitHub Actions for better maintainability

### Fixed
- Reset counter baselines after long scrape gaps to avoid spikes on recovery

## [0.3.0] - 2026-02-19

### Added
- Firewall rule metrics with byte and packet counters:
  - `mikrotik_firewall_rule_bytes_total{rule_id, chain, action, ip_version, section}`
  - `mikrotik_firewall_rule_packets_total{rule_id, chain, action, ip_version, section}`
- Support for collecting firewall rules from all RouterOS firewall tables:
  - `/ip/firewall/filter` and `/ipv6/firewall/filter`
  - `/ip/firewall/nat` and `/ipv6/firewall/nat`
  - `/ip/firewall/mangle` and `/ipv6/firewall/mangle`
  - `/ip/firewall/raw` and `/ipv6/firewall/raw`
- Automatic delta calculation for firewall rule counters with proper reset handling
- IPv4 and IPv6 support for all firewall rule metrics
- Automatic cleanup of stale firewall rule labels
- GitHub Actions workflow for automatic cache cleanup
- Manual release trigger via `workflow_dispatch` in CI

### Changed
- Added `section` label to firewall metrics to distinguish rules by firewall section (filter, nat, mangle, raw)
- Added `rule_id` label to firewall metrics for unique identification of each rule
- Updated documentation and usage examples to reflect the new firewall metrics
- Updated Grafana dashboard with firewall rules monitoring panels
- Improved dashboard legend formatting and sorting
- Corrected dashboard panel units (Bps instead of bps)
- Optimized ARM64 Docker build caching performance
- CI now uses native ARM64 runner for Docker builds
- CI build and release jobs separated to avoid race conditions

### Fixed
- Docker TARGETARCH mapping to correct Rust target triples
- Dockerfile cache mount syntax

## [0.2.5] - 2026-02-18
### Added
- Certificate expiration monitoring metrics with `mikrotik_certificate_days_until_expiry` gauge
- Support for parsing both ISO (YYYY-MM-DD) and legacy (MMM/DD/YYYY) certificate date formats
- Comprehensive integration tests with environment variable support
- Property-based testing for protocol encoding/decoding
- Certificate cleanup logic to prevent memory leaks

### Changed
- Refactored MikroTik response parsing into dedicated `responses` module for better maintainability
- Improved certificate parser to support both ISO (YYYY-MM-DD) and legacy (MMM/DD/YYYY) date formats
- Enhanced Grafana dashboard with certificate expiry timeline panel
- Updated MikroTik client to use `/certificate/print .detail` command
- Moved WireGuard types to `types.rs` for consistency
- Cleaned up `connection/` module (now only TCP + protocol)
- Improved integration test coverage and added property-based testing
- Query performance improvements in dashboard queries

### Fixed
- Test failures in `test_encode_length_extremely_large`
- Certificate parsing with actual dates in tests
- Sorting issues in WireGuard peer table
- Connection pool tests to use public API

## [0.2.4] - 2026-02-17

### Added
- Configuration validation with startup connectivity testing
- New environment variables for startup connectivity testing:
  - `STARTUP_CONNECTIVITY_TEST` - Enable/disable startup connectivity testing
  - `STARTUP_CONNECTIVITY_TIMEOUT_SECS` - Timeout for connectivity tests
  - `STRICT_STARTUP_MODE` - Fail startup if any router is unreachable
- Enhanced documentation for public APIs and configuration options
- Publication metadata for crates.io
- Links to official Grafana dashboard (ID: 24875)

### Changed
- Optimized metrics registry with DashMap for better concurrency performance
- Reduced lock contention for read-heavy operations with large numbers of interfaces
- Improved concurrent access allowing multiple threads to work simultaneously
- Faster metric updates by removing blocking mutex operations
- Better cleanup performance for large datasets
- Improved project documentation with installation instructions and badges

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
