# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-02-10

### Added
- WireGuard monitoring support
- Open connections stats panel with IPv4/IPv6 support

### Fixed
- Stale system_info gauge issue
- Conntrack metrics isolation for multi-router configurations
- AtomicUsize underflow race condition in connection pool
- Proper WireGuard handshake timestamp parsing

### Changed
- Improved Grafana dashboard with better visualizations and metadata
- Refactored WireGuard peer identification
- Removed redundant metrics
- Resolved clippy warnings

### Removed
- Unused zeroize dependency

## [0.1.1] - 2026-02-09

### Fixed
- Health check endpoint now properly returns 503 when routers have errors
- Connection pool backoff algorithm improvements
- RouterOS authentication method selection

## [0.1.0] - 2025-11-15

### Added
- Initial release
- Prometheus exporter for MikroTik RouterOS devices
- Interface, system, and connection tracking metrics
- HTTP `/metrics` and `/health` endpoints
- Configurable via environment variables
- Connection pooling with exponential backoff
- Multi-router support