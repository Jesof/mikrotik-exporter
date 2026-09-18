# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added
- Container images carry standard OCI labels (`title`, `description`, `source`, `licenses`) for
  registry and tooling metadata.

### Changed
- Release creation authenticates with a short-lived GitHub App installation token minted from the
  `RELEASE_APP_ID` / `RELEASE_APP_PRIVATE_KEY` secrets instead of a long-lived personal access
  token.
- Published image tags: `latest` now moves only on a release and always points at the newest stable
  release, while `main` remains the rolling `main` build. The pre-1.0 major-line `:0` tag and the
  duplicate `vX.Y.Z` tag are no longer published; release images are promoted from the verified
  `main` digest as `X.Y.Z` and `X.Y` and are never rebuilt.
- CI selects jobs from a single reusable `Detect Changes` workflow: documentation changes run docs
  lint (markdownlint and link checking), workflow changes run actionlint and shellcheck, container
  or crate changes run Docker validation, and coverage runs on `main` and schedules only. CodeQL runs
  per language (Rust only for Rust changes, Actions only for workflow changes) with queries
  configured in `.github/codeql/codeql-config.yml`. Main image publication runs only for
  container-affecting changes.
- `RouterConfig::validate` and `RouterTlsConfig::server_name_for_address` now return `AppError`
  instead of plain `String`, so configuration errors are uniformly typed across the crate.
- Log statements were switched to structured fields (for example `router = %name`) for uniform,
  queryable tracing output.
- Large `MetricsRegistry` cleanup routines were split into single-responsibility helpers.
- `MetricsRegistry` internals were split into per-domain sub-registries (`interface`, `system`,
  `conntrack`, `wireguard`, `certificate`, `firewall`, `scrape`, `pool`), removing a monolithic
  structure. The public API is unchanged.
- Added Criterion benchmarks for the hot metric paths (`encode_metrics`, `update_metrics`). They
  run locally with `cargo bench` and are not part of the CI gate.

## [0.5.0] - 2026-09-17

### Fixed
- Treat per-query failures (an unsupported or denied firewall, WireGuard, or
  conntrack table) as group-level results instead of connection errors: a
  protocol-clean connection is no longer discarded and pool backoff no longer
  suppresses the whole group, including its usable data.
- Preserve firewall counter baselines during partial snapshots by refreshing their
  TTL, and reset (rather than re-seed) interface and firewall counters when a
  series returns after being removed. This removes a recovery spike in
  `mikrotik_interface_*_total` and `mikrotik_firewall_rule_*_total`.
- Keep `count-only` failures typed instead of silently degrading an empty-table
  check, so a timeout cannot masquerade as a count mismatch and desynchronize the
  rest of the group.
- Update CPU, memory, and system metadata even when `uptime` is unparseable,
  instead of dropping all system metrics.
- Report the certificate group as usable but incomplete (success 1, completeness 0)
  when RouterOS returns certificate rows but none carries a usable expiry, instead
  of exporting a silent empty Complete snapshot. A router whose certificates all
  lack a usable expiry (for example only a template) shows the group as partial;
  routers with at least one usable row are unaffected.

### Changed
- **Breaking:** `InterfaceStats::rx_errors` and `tx_errors` are now `Option<u64>`.
  `None` means the router did not report the counter, so the exported
  `mikrotik_interface_rx_errors_total` / `mikrotik_interface_tx_errors_total` is left
  unchanged rather than reset to zero, and a counter that appears later establishes a
  baseline instead of adding the router's lifetime count. Update library callers that
  construct `InterfaceStats` or read these fields.
- `/health` freshness is `3 × collection interval`, independent of
  `GAP_RESET_THRESHOLD_SECONDS`; consecutive errors are matched against the full
  router connection identity (address, username, password, TLS).
- Cache the verified TLS trust store/connector per router and resolve it outside
  the connection deadline, so loading system roots cannot surface as a connect
  timeout.
- CI runs on pull requests, schedules, manual dispatches, and `main` pushes instead of repeating
  the full quality suite on every feature-branch push.
- Release recovery is repeatable for an existing tag, and release images expose exact, minor-line,
  and major-line tags in addition to the immutable source-SHA tag; `latest` remains the checked
  `main` image.
- Release workflows reuse successful exact-SHA main CI, build release binaries without repeating
  tests, and promote the already scanned immutable Docker image instead of rebuilding it.
- Release tags must be annotated and cryptographically signed; Dependabot auto-merge excludes CI,
  release, Docker, and dependency configuration files.

### Breaking Migration

`0.5.0` compatibility changes. Metric names, units, types, and labels are unchanged.

- **Rust API:** `InterfaceStats::rx_errors` and `tx_errors` are now `Option<u64>`. Library callers
  that construct `InterfaceStats` or read these fields must handle `None`. `None` means RouterOS
  did not report the counter, so `mikrotik_interface_rx_errors_total` /
  `mikrotik_interface_tx_errors_total` keep their previous value (or stay absent) instead of being
  reset to zero.
- **`/health` freshness:** healthy requires a complete success no older than
  `3 × COLLECTION_INTERVAL_SECONDS`, independent of `GAP_RESET_THRESHOLD_SECONDS`. Alerts or probes
  that relied on the previous `max(3 × interval, gap reset threshold)` window must be updated.
- **Certificate completeness:** the `certificates` group can report success with completeness `0`
  when rows are returned without a usable expiry. Alerting that treats
  `mikrotik_group_collection_success == 1` as data-present should also check
  `mikrotik_group_collection_complete` for the `certificates` group.

## [0.4.0] - 2026-09-15

### Added
- Added configurable gap reset threshold via `GAP_RESET_THRESHOLD_SECONDS` environment variable
- Enhanced connection pool backoff strategy for faster recovery after network outages
- Optional verified RouterOS API-SSL per router via `tls`, with system trust roots, an optional
  `server_name`, and a custom PEM `ca_file`; legacy single-router TLS via `ROUTEROS_TLS`.
- `/live` and `/ready` process probes, separate from cached `/health` router diagnostics.
- Per-group success, completeness, and last-complete-success timestamp gauges for
  `system_interfaces`, `conntrack`, `wireguard`, `certificates`, and `firewall`.
- `mikrotik_conntrack_dropped_series` gauge reporting latest usable snapshot series omitted by
  the 1024 retained-series-per-router cap, including partial snapshots.
- Configuration-independent `--version` / `-V`; deterministic fixture/loopback integration tests
  and explicitly ignored real-device connectivity testing.

### Changed
- Improved gap detection mechanism to be more responsive to connection issues
- Optimized counter reset logic after connection restoration
- Enhanced error tracking for different metric groups
- **Breaking:** standardized CPU utilization to a ratio and three duration metrics to seconds;
  clarified WireGuard handshake timestamp naming. See the migration table below.
- **Breaking:** configuration loading returns `Result<Config>` and fails on malformed JSON,
  unknown router/TLS fields, invalid values, invalid routers, and duplicate names. Invalid
  `ROUTERS_CONFIG` no longer falls back to legacy settings or filters out invalid entries.
- **Breaking:** complete collection is now required for router success/freshness; partial data
  updates usable groups while recording a scrape error. Required malformed numeric data fails
  its fetch; invalid snapshots no longer update metrics with fabricated zeroes.
- **Breaking:** collector startup returns a supervised `JoinHandle<Result<()>>`; the framing
  helper `encode_length` is private. Public configuration, errors, and metric input types reflect
  strict validation and explicit complete/partial/failed collection status.
- **Breaking:** Rust 1.98.0 is the MSRV and pinned compiler, synchronized with Clippy and Docker.
- Independent non-overlapping router schedules skip missed ticks, so slow routers do not block
  others. The aggregate cycle duration measures progress across all configured routers.
- Supervised startup/HTTP/collector tasks, readiness transitions, and bounded shutdown with task joins.
- `build-docker.sh` is build-only. Deployment guidance uses process probes, verified TLS,
  freshness-based alerts, the correct ServiceMonitor port, and actual Kubernetes manifests.
- Full CI on pushes, PRs, schedules, and manual runs; required `Check` aggregates Rust, coverage,
  workflow, and native multi-architecture Docker validation. Actions are SHA-pinned.
- Releases verify exact signed tag/Cargo version, main ancestry, and successful main CI for the same
  SHA, build release targets, and attest binaries/checksums and the promoted image.
- Updated public contribution/security policies and issue/PR guidance.

### Fixed
- Accept RouterOS interface snapshots that omit `rx-error` or `tx-error` for
  interface types or versions where those counters are unavailable.
- Query only the required certificate properties so RouterOS detailed certificate
  output cannot produce duplicate response attributes.
- Upgrade Alpine runtime packages during image builds to include security fixes, including
  OpenSSL CVE-2026-14456 in `libcrypto3` and `libssl3`.
- Use IPv4 loopback for Docker's healthcheck to match the default HTTP listener and avoid
  false unhealthy status when `localhost` resolves to `::1`.
- Read count-only values from terminal `!done` attributes so valid empty firewall/WireGuard
  tables do not fail collection; encode property-list/detail requests as RouterOS attributes.
- Isolate pooled connections by password as well as username/TLS; successful authentication
  alone no longer resets consecutive command failures and defeats group backoff.
- Remove interface series on complete empty registry snapshots and remove superseded metadata
  immediately when a router is removed. Docker's built-in healthcheck uses `/live`.
- Track rules first observed in partial firewall snapshots for subsequent cleanup, and supersede
  changed metadata during partial updates without removing unobserved rules.
- Reject WireGuard byte counts outside the signed gauge range instead of exporting negative values.
- Fixed issue with missing metrics after connection restoration by implementing more aggressive baseline reset
- Resolved problems with stale metrics persistence after prolonged network outages
- Bounded and fallible protocol framing, typed transport/protocol errors, and safe handling of
  malformed, oversized, truncated, or timed-out router responses.
- Cancellation-safe transport reuse, group-aware pool state/backoff, and credential/TLS-aware
  connection identity; failed or interrupted commands cannot return a dirty stream to the pool.
- Conntrack cardinality remains bounded across retained partial data; removed routers and stale
  dynamic metadata, including superseded `system_info`, are cleaned up.
- Initialize router/group freshness and conntrack observability at zero so never-success states
  remain visible before collection and after failures.

### Breaking Migration

Upgrade exporter, dashboards, recording rules, alerts, and library callers together. Old metric
names are not aliases:

| Old metric | New metric | Value conversion |
| --- | --- | --- |
| `mikrotik_scrape_duration_milliseconds` | `mikrotik_scrape_duration_seconds` | Divide old values/thresholds by 1000; new gauge is floating-point seconds |
| `mikrotik_collection_cycle_duration_milliseconds` | `mikrotik_collection_cycle_duration_seconds` | Divide by 1000; remains an unlabeled aggregate gauge |
| `mikrotik_conntrack_update_duration_milliseconds` | `mikrotik_conntrack_update_duration_seconds` | Divide by 1000; floating-point seconds |
| `mikrotik_system_cpu_load` | `mikrotik_system_cpu_load_ratio` | Divide by 100; e.g. threshold 80 becomes 0.8 |
| `mikrotik_wireguard_peer_latest_handshake` | `mikrotik_wireguard_peer_latest_handshake_timestamp_seconds` | Rename only; Unix seconds, 0 when absent |

- Remove obsolete milliseconds/CPU percentage conversions from queries and use the matching
  dashboard revision. WireGuard RX/TX byte metrics remain gauges; interface/firewall totals remain
  counters. Pool size/active and collection-cycle metrics have no `router` label.
- Replace lifetime-counter availability alerts with router/group last-success timestamps:
  `timestamp == 0` covers never-success, and `time() - timestamp > threshold` covers stale data.
  A partial collection no longer increments `mikrotik_scrape_success_total` or advances router
  freshness. Group success can be 1 while completeness is 0; group freshness advances only on
  complete results. Unsupported/denied commands may keep a group incomplete.
  A critical system/interfaces failure or invalid numeric snapshot rejects the overall production
  collection; registry update methods require validated input from direct library callers.
- Conntrack exports at most 1024 retained series per router, ordered deterministically by
  `(ip_version, src_address, protocol)`; totals over those series may undercount the router.
  Alert on `mikrotik_conntrack_dropped_series > 0`. This gauge counts omitted distinct series,
  not dropped packets or a lifetime total. Select `mikrotik_system_info == 1` for current metadata;
  superseded entries become 0 and expire with the 30-minute dynamic-label TTL.
- Fix invalid configuration before rollout: integer ranges are collection 1–86400 seconds,
  gap reset 1–604800 seconds, and startup timeout 1–300 seconds; booleans are exactly `true`/`false`.
  `SERVER_ADDR` must be an IP socket address. Strict startup requires enabled connectivity tests
  and at least one router. Router names must be unique. Remove unknown JSON fields.
- Update Rust callers to `let config = Config::from_env()?;`, validate programmatic configs,
  and add `tls: None` or `Some(RouterTlsConfig { ... })` to `RouterConfig` literals. Retain,
  supervise, signal, and await collector handles, handling both `JoinError` and the inner `Result`.
  Use supported public APIs instead of `encode_length`; private framing tests now live beside
  the implementation. Handle typed error variants and propagate fallible metric encoding.
- TLS is opt-in: omitted/null per-router `tls` and unset legacy `ROUTEROS_TLS` preserve plaintext.
  An empty TLS object enables system roots. `ca_file` replaces system roots; `server_name`
  overrides the identity derived from the address host. Legacy TLS must be an object, not `null`.
  Port 8729 alone does not enable TLS. Mount the CA file, configure the RouterOS server certificate,
  restrict the exporter source address, and restart to apply configuration changes.
- Point process probes to `/live` and `/ready`. `/health` remains cached router diagnostics and
  may return 503 while the exporter is live and ready. Custom HTTP embeddings should manage
  readiness through `AppState::router_with_readiness`; `create_router` assumes already initialized.
- Build with Rust 1.98.0. Explicitly run the ignored real-device test only with authorization;
  ordinary test runs no longer discover and contact devices from local credentials.

## [0.3.3] - 2026-02-23

### Added
- Added metadata gauges `mikrotik_interface_info` and `mikrotik_firewall_rule_info` for stable joins

### Changed
- Switched counter labels to stable `id` keys for interfaces, WireGuard peers, certificates, and firewall rules
- Updated Grafana dashboard queries to join metadata from info gauges and adjusted interface variable source
- Refreshed README metric lists and label descriptions to match the new label model

### Fixed
- Cleaned up stale dynamic label series via TTL to prevent unbounded growth when metadata changes

### Removed
- Removed interface, WireGuard peer, firewall rule, and certificate counters' comment/name labels in favor of info metrics

## [0.3.2] - 2026-02-23

### Added
- Added `comment` label to all applicable metrics (interfaces, WireGuard peers, certificates, and firewall rules)
- Enhanced Grafana dashboard with comment labels

### Fixed
- Fixed an unbounded metric memory leak caused by stale firewall rule labels not being garbage collected when rule comments change
- Run Docker build on tag pushes

### Removed
- Removed unused `WireGuardInterfaceLabels` and `/interface/wireguard/print` API call, optimizing metric scraping performance

## [0.3.1] - 2026-02-21

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
