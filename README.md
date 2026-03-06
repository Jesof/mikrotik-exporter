# MikroTik Prometheus Exporter

[![Crates.io](https://img.shields.io/crates/v/mikrotik-exporter.svg)](https://crates.io/crates/mikrotik-exporter)
[![GitHub release](https://img.shields.io/github/v/release/jesof/mikrotik-exporter.svg)](https://github.com/jesof/mikrotik-exporter/releases)
[![Grafana](https://img.shields.io/badge/Grafana-24875-orange.svg?logo=grafana)](https://grafana.com/grafana/dashboards/24875-mikrotik-router-monitoring/)
[![Docs.rs](https://docs.rs/mikrotik-exporter/badge.svg)](https://docs.rs/mikrotik-exporter)
[![Rust](https://github.com/jesof/mikrotik-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/jesof/mikrotik-exporter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Prometheus exporter for MikroTik RouterOS API with multi-router support and async architecture.

## Quick Start

```bash
# Cargo
cargo install mikrotik-exporter

# Docker
docker run -p 9090:9090 \
  -e ROUTERS_CONFIG='[{"name":"router1","address":"192.168.88.1:8728","username":"admin","password":"pass"}]' \
  ghcr.io/jesof/mikrotik-exporter:latest

# Binary
ROUTERS_CONFIG='[...]' ./mikrotik-exporter

# Kubernetes
kubectl apply -k k8s/
```

## Metrics

| Metric                                   | Type    | Description                       |
| ---------------------------------------  | ------- | --------------------------------- |
| `mikrotik_interface_rx_bytes_total`      | counter | Received bytes                    |
| `mikrotik_interface_tx_bytes_total`      | counter | Transmitted bytes                 |
| `mikrotik_interface_info`                | gauge   | Interface metadata (name, comment)|
| `mikrotik_system_cpu_load`               | gauge   | CPU load (%)                      |
| `mikrotik_system_free_memory_bytes`      | gauge   | Free memory                       |
| `mikrotik_wireguard_peer_rx_bytes`       | gauge   | WireGuard RX bytes                |
| `mikrotik_wireguard_peer_info`           | gauge   | WireGuard metadata                |
| `mikrotik_firewall_rule_bytes_total`     | counter | Firewall traffic                  |

[Full metrics list →](#full-metrics-list)

## Configuration

### Environment Variables

```bash
SERVER_ADDR=0.0.0.0:9090                    # HTTP server bind address
ROUTERS_CONFIG=[{...}]                      # JSON array of routers (recommended)
COLLECTION_INTERVAL_SECONDS=30              # Metrics collection interval
GAP_RESET_THRESHOLD_SECONDS=60              # Threshold for resetting counter baselines after scrape gaps
STARTUP_CONNECTIVITY_TEST=false             # Check router availability at startup
STARTUP_CONNECTIVITY_TIMEOUT_SECS=10        # Connectivity test timeout (seconds)
STRICT_STARTUP_MODE=false                   # Exit if routers are unavailable
RUST_LOG=info                               # Logging level
ROUTEROS_ADDRESS=192.168.88.1:8728          # Legacy: RouterOS API address (single router)
ROUTEROS_USERNAME=admin                     # Legacy: username (default: admin)
ROUTEROS_PASSWORD=                          # Legacy: password (default: empty)
```

If `ROUTERS_CONFIG` is not set, legacy configuration
`ROUTEROS_ADDRESS/ROUTEROS_USERNAME/ROUTEROS_PASSWORD` is used with router name `default`.

### Router Connectivity Check at Startup

New options allow checking availability of all configured routers at service startup:

- `STARTUP_CONNECTIVITY_TEST=true` - enables router availability check at startup
- `STARTUP_CONNECTIVITY_TIMEOUT_SECS=10` - timeout for each check (default: 10 seconds)
- `STRICT_STARTUP_MODE=true` - exits the service with error code if any router is unavailable

Usage example:

```bash
# Check router availability at startup, but continue even if some are unavailable
STARTUP_CONNECTIVITY_TEST=true ./mikrotik-exporter

# Check router availability and exit if any router is unavailable
STARTUP_CONNECTIVITY_TEST=true STRICT_STARTUP_MODE=true ./mikrotik-exporter
```

### ROUTERS_CONFIG Format

```json
[
  {
    "name": "router-name",
    "address": "192.168.88.1:8728",
    "username": "admin",
    "password": "password"
  }
]
```

## Endpoints

| Path       | Description                                  | Response Code                |
| ---------- | -------------------------------------------- | ---------------------------- |
| `/metrics` | Prometheus metrics                           | 200                          |
| `/health`  | Health check with router connectivity test   | 200 (OK) / 503 (unavailable) |

Health status policy:

- `healthy`: router has successful scrapes and is below consecutive error threshold.
- `degraded`: router has scrape errors, too many consecutive connection errors, or has not yet had a successful scrape.

## Deployment

- [Kubernetes](DEPLOYMENT.md#kubernetes)
- [Docker & Docker Compose](EXAMPLES.md#docker-compose---production-stack)
- [Prometheus integration](DEPLOYMENT.md#prometheus)
- [Grafana Dashboard (ID: 24875)](https://grafana.com/grafana/dashboards/24875-mikrotik-router-monitoring/)

## RouterOS Requirements

```bash
# Enable API
/ip service set api address=0.0.0.0/0 disabled=no port=8728

# Create user
/user group add name=monitoring policy=api,read
/user add name=prometheus group=monitoring password=secure-password
```

## Development

```bash
# Run
cargo run

# Tests
cargo test

# Lint (pedantic warnings)
cargo clippy --all-targets --all-features --locked

# Lint (CI strict mode)
cargo clippy --all-targets --all-features --locked -- -D warnings

# Integration tests (require configured MikroTik device)
cargo test --test integration_tests

# Build
cargo build --release
```

To run integration tests, configure connection to a real MikroTik device via environment variables in `.env` file:

```bash
# Example .env file for integration tests
ROUTEROS_ADDRESS=192.168.88.1:8728
ROUTEROS_USERNAME=admin
ROUTEROS_PASSWORD=your_password
```

Integration tests are automatically skipped if environment variables are not configured.

[Architecture & API →](#project-architecture)

## License

MIT - see [LICENSE](LICENSE)

---

## Full Metrics List

### Interfaces (Labels: router, id)

| Metric                                | Type    | Description                   |
| ------------------------------------- | ------- | ----------------------------- |
| `mikrotik_interface_rx_bytes_total`   | counter | Received bytes                |
| `mikrotik_interface_tx_bytes_total`   | counter | Transmitted bytes             |
| `mikrotik_interface_rx_packets_total` | counter | Received packets              |
| `mikrotik_interface_tx_packets_total` | counter | Transmitted packets           |
| `mikrotik_interface_rx_errors_total`  | counter | Receive errors                |
| `mikrotik_interface_tx_errors_total`  | counter | Transmit errors               |
| `mikrotik_interface_running`          | gauge   | Status (1=running, 0=stopped) |
| `mikrotik_interface_info`             | gauge   | Metadata (name, comment)      |

### System (Labels: router, version, board)

| Metric                               | Type   | Description                                      |
| ------------------------------------ | ------ | ------------------------------------------------ |
| `mikrotik_system_cpu_load`           | gauge  | CPU load (%)                                     |
| `mikrotik_system_free_memory_bytes`  | gauge  | Free memory                                      |
| `mikrotik_system_total_memory_bytes` | gauge  | Total memory                                     |
| `mikrotik_system_uptime_seconds`     | gauge  | System uptime                                    |
| `mikrotik_system_info`               | gauge  | System info (value=1, labels: version, board)    |

### Service Metrics (Labels: router)

| Metric                                            | Type    | Description                               |
| ------------------------------------------------- | ------- | ----------------------------------------- |
| `mikrotik_scrape_success_total`                   | counter | Successful scrapes                        |
| `mikrotik_scrape_errors_total`                    | counter | Scrape errors                             |
| `mikrotik_scrape_duration_milliseconds`           | gauge   | Last scrape duration                      |
| `mikrotik_scrape_last_success_timestamp_seconds`  | gauge   | Unix timestamp of last successful scrape  |
| `mikrotik_connection_consecutive_errors`          | gauge   | Consecutive connection errors             |
| `mikrotik_collection_cycle_duration_milliseconds` | gauge   | Full collection cycle duration            |
| `mikrotik_connection_pool_size`                   | gauge   | Connection pool size                      |
| `mikrotik_connection_pool_active`                 | gauge   | Active connections in pool                |

### Connection Tracking (Labels: router, src_address, protocol, ip_version)

| Metric                                | Type   | Description                               |
| --------------------------------------| ------ | ----------------------------------------- |
| `mikrotik_connection_tracking_count`  | gauge  | Connection count by src/protocol/ip       |

### Connection Tracking Observability (Labels: router)

| Metric                                            | Type  | Description                                       |
| ------------------------------------------------- | ----- | ------------------------------------------------- |
| `mikrotik_conntrack_active_series`                | gauge | Active conntrack series for the router            |
| `mikrotik_conntrack_update_duration_milliseconds` | gauge | Last conntrack update duration in milliseconds    |

### WireGuard Peers (Labels: router, id)

| Metric                                     | Type   | Description                                   |
| ------------------------------------------ | ------ | --------------------------------------------- |
| `mikrotik_wireguard_peer_rx_bytes`         | gauge  | Received bytes from peer                      |
| `mikrotik_wireguard_peer_tx_bytes`         | gauge  | Transmitted bytes to peer                     |
| `mikrotik_wireguard_peer_latest_handshake` | gauge  | Unix timestamp of last handshake              |
| `mikrotik_wireguard_peer_info`             | gauge  | Metadata (name, endpoint, comment, etc.)      |

### Certificates (Labels: router, id, name)

| Metric                                      | Type   | Description                               |
| ------------------------------------------- | ------ | ----------------------------------------- |
| `mikrotik_certificate_days_until_expiry`    | gauge  | Days until certificate expiry             |

The `mikrotik_certificate_days_until_expiry` metric tracks the number of days until certificate expiration on the router.
Both RouterOS certificate expiration date formats are supported:

- ISO format (YYYY-MM-DD) - modern format
- Legacy format (MMM/DD/YYYY) - classic format

Metric values:

- Positive values: number of days until expiration
- Negative values: number of days since expiration (expired certificates)
- Zero value: certificate expires today

For monitoring, you can use alerts, for example:

- Warning when `mikrotik_certificate_days_until_expiry < 30` (certificate expires in less than 30 days)
- Critical when `mikrotik_certificate_days_until_expiry < 0` (certificate already expired)

### Firewall Rules (Labels: router, id, chain, action, ip_version, section)

| Metric                                 | Type    | Description                          |
| -------------------------------------- | ------- | ------------------------------------ |
| `mikrotik_firewall_rule_bytes_total`   | counter | Bytes matching firewall rules        |
| `mikrotik_firewall_rule_packets_total` | counter | Packets matching firewall rules      |
| `mikrotik_firewall_rule_info`          | gauge   | Metadata (comment)                   |

## Project Architecture

```tree
src/
├── lib.rs                  # Public library
├── main.rs                 # Entry point
├── prelude.rs              # Re-exports
├── startup/                # Startup connectivity policy
│   ├── check.rs            # Router connectivity checks
│   └── policy.rs           # Startup mode policy handling
├── api/                    # HTTP handlers
│   ├── health.rs           # Health domain policy
│   └── handlers/           # HTTP endpoint handlers
├── collector/              # Background metrics collection
│   ├── router_task.rs      # Per-router collection task
│   └── cleanup.rs          # Periodic cleanup task
├── config/                 # Configuration loading
│   ├── defaults.rs         # Default values
│   ├── env_vars.rs         # Environment variable names
│   ├── loader.rs           # Env parsing and bootstrap helpers
│   ├── router.rs           # RouterConfig model + validation
│   ├── tests.rs            # Config unit tests
│   └── mod.rs
├── error.rs                # Error types
├── metrics/                # Prometheus metrics
│   ├── labels.rs           # Label definitions
│   ├── parsers.rs          # Response parsers
│   ├── registry/           # Metrics registry (init/update/cleanup/scrape)
│   └── tests.rs            # Metric tests
└── mikrotik/               # RouterOS API client
    ├── client/              # Client implementation split by metric groups
    │   ├── mod.rs           # Client module exports
    │   └── groups/          # Metric group implementations
    │       ├── common.rs    # Shared parsing helpers
    │       ├── conntrack.rs # Connection tracking collection
    │       ├── firewall.rs  # Firewall-related collection
    │       ├── mod.rs       # Group orchestration
    │       ├── system.rs    # System/resource collection
    │       └── vpn.rs       # WireGuard/certificates collection
    ├── connection/         # Connection handling (auth/protocol)
    ├── pool/               # Connection pool
    │   ├── guard.rs         # RAII guard
    │   ├── ops.rs           # Pool operations
    │   ├── types.rs         # Internal state
    │   └── mod.rs
    ├── responses/          # Response parsers
    ├── types.rs            # Type definitions
    └── mod.rs              # Module exports
```

### Using as a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
mikrotik-exporter = "0.3.3"
```

```rust
use std::sync::Arc;

use mikrotik_exporter::{
    AppState, Config, ConnectionPool, MetricsRegistry, Result, create_router,
    start_collection_loop,
};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env();
    let metrics = MetricsRegistry::new();
    let pool = Arc::new(ConnectionPool::new());
    let state = Arc::new(AppState {
        config: config.clone(),
        metrics: metrics.clone(),
        pool: pool.clone(),
    });

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    start_collection_loop(shutdown_rx, Arc::new(config), metrics, pool);

    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:9090").await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
```
