# MikroTik Prometheus Exporter

[![Crates.io](https://img.shields.io/crates/v/mikrotik-exporter.svg)](https://crates.io/crates/mikrotik-exporter)
[![GitHub release](https://img.shields.io/github/v/release/jesof/mikrotik-exporter.svg)](https://github.com/jesof/mikrotik-exporter/releases)
[![Docs.rs](https://docs.rs/mikrotik-exporter/badge.svg)](https://docs.rs/mikrotik-exporter)
[![Rust CI](https://github.com/jesof/mikrotik-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/jesof/mikrotik-exporter/actions/workflows/ci.yml)

Prometheus exporter for MikroTik RouterOS, with independent per-router collection schedules,
connection pooling, optional verified TLS, and OpenMetrics output.

This README describes the current source tree, including unreleased changes. For upgrades from
0.3.3, follow the [0.4.0 migration guide](CHANGELOG.md#040---2026-09-15). Published 0.3.3 packages
do not include those changes.

## Quick Start

Build the current source with the pinned Rust **1.98.0** toolchain (also the MSRV; edition 2024):

```bash
cargo build --release --locked
```

Create a private `.env` from [`.env.example`](.env.example), configure a dedicated RouterOS
user and TLS as described below, then run:

```bash
./target/release/mikrotik-exporter
```

The binary loads `.env` from the working directory. `--version` (or `-V`) prints the version
without loading configuration or contacting routers; other command-line arguments are rejected.
To install the latest *published* version, use `cargo install mikrotik-exporter --locked`.

For Docker and Kubernetes, see [DEPLOYMENT.md](DEPLOYMENT.md).

## Configuration

| Variable | Default | Meaning / accepted values |
| --- | --- | --- |
| `SERVER_ADDR` | `0.0.0.0:9090` | HTTP bind IP socket address, e.g. `127.0.0.1:9090` or `[::]:9090` |
| `ROUTERS_CONFIG` | unset | JSON array of routers; takes precedence over legacy router variables |
| `COLLECTION_INTERVAL_SECONDS` | `30` | Per-router interval, integer 1–86400 seconds |
| `GAP_RESET_THRESHOLD_SECONDS` | `60` | Counter baseline reset threshold, integer 1–604800 seconds |
| `STARTUP_CONNECTIVITY_TEST` | `false` | `true` / `false`: test connections before becoming ready |
| `STARTUP_CONNECTIVITY_TIMEOUT_SECS` | `10` | Per-router startup test timeout, integer 1–300 seconds |
| `STRICT_STARTUP_MODE` | `false` | `true` / `false`: fail startup if a configured router fails its test |
| `RUST_LOG` | `info` | Tracing filter |
| `ROUTEROS_ADDRESS` | unset | Legacy single router `host:port`, named `default` |
| `ROUTEROS_USERNAME` | `admin` | Legacy username; use a dedicated monitoring user |
| `ROUTEROS_PASSWORD` | empty | Legacy password; set a strong secret |
| `ROUTEROS_TLS` | unset | Legacy TLS JSON object, e.g. `{"server_name":"router.example.net"}` |

Configuration loading is fallible: malformed JSON, unknown router/TLS fields, invalid numbers
or booleans, invalid addresses, and duplicate router names fail startup. An invalid
`ROUTERS_CONFIG` **never falls back** to legacy variables. Defaults apply only to unset variables.
An empty router list is allowed outside strict mode, but `/health` reports degraded.
`STRICT_STARTUP_MODE=true` requires `STARTUP_CONNECTIVITY_TEST=true` and at least one router.

### Router JSON and TLS

Store this JSON in a protected configuration/secret, replacing the example password:

```json
[
  {
    "name": "edge-router",
    "address": "192.0.2.1:8729",
    "username": "prometheus",
    "password": "REPLACE_WITH_A_STRONG_SECRET",
    "tls": {
      "server_name": "router.example.net",
      "ca_file": "/etc/mikrotik-exporter/router-ca.pem"
    }
  }
]
```

- Router names must be unique, 1–128 ASCII alphanumeric, underscore, or hyphen characters.
- Addresses require an explicit port 1–65535; IPv6 uses `[address]:port`. DNS hosts are supported.
- Usernames must be nonblank and at most 64 bytes. Passwords are stored as `SecretString`;
  empty passwords are accepted for compatibility, not recommended for deployment.
- `"tls": {}` enables TLS with system trust roots and the address host as the verified identity.
- `server_name` overrides the verified DNS name or IP address (useful when connecting by IP).
- `ca_file` selects a PEM trust bundle **instead of** system roots; mount it read-only and make it
  readable by the exporter. Invalid/empty bundles and certificate validation failures fail connections.
- Omitting `tls`, or setting it to `null`, selects **plaintext**, regardless of port. Setting port
  8729 alone does not enable TLS. There is no insecure verification bypass or client-certificate option.
- Legacy `ROUTEROS_TLS` accepts an object (`{}` enables system roots); leave it unset for plaintext.
  The string `null` is not a valid legacy TLS object.

TLS is configured on each connection. Trust files must be available when connecting; changing
configuration, credentials, or trust material should be followed by an exporter restart.

## RouterOS Requirements

Use an installed server certificate with a matching subject alternative name and a chain trusted
by the exporter. Replace `router-api-cert` with its RouterOS certificate name and `192.0.2.10/32`
with the exporter's source address **as seen by the router**, including any NAT:

```routeros
/user group add name=monitoring policy=read,api
/user add name=prometheus group=monitoring address=192.0.2.10/32 password="REPLACE_WITH_A_STRONG_SECRET"
/ip service set api-ssl disabled=no port=8729 certificate=router-api-cert address=192.0.2.10/32
```

Restrict firewall access to that source too. Disable the plaintext `api` service when no other
client needs it. The exporter requires certificate-based API-SSL; certificate-less anonymous TLS
is unsupported. Start with `read,api` permissions and investigate denied commands before granting
more access. RouterOS features absent or inaccessible on a device may produce incomplete groups.

**Plaintext API exposes credentials and metrics to network observers.** Use verified TLS or an
independently encrypted, isolated management path. HTTP endpoints also expose topology and have
no built-in authentication or server-side TLS; keep them private. See [SECURITY.md](SECURITY.md).

## Endpoints

| Path | Purpose | Status |
| --- | --- | --- |
| `/metrics` | Cached OpenMetrics exposition; does not initiate router collection | 200; 500 on encoding failure |
| `/live` | Process HTTP liveness, independent of routers | 200 while serving |
| `/ready` | Binary initialization and shutdown readiness, independent of router freshness | 200 ready; 503 initializing/stopping |
| `/health` | Per-router diagnostics from the latest collection state; no active connectivity test | 200 healthy; 503 degraded |

Use `/live` for startup/liveness and `/ready` for readiness probes. Router outages should produce
alerts, not restart loops or prevent scraping the failure metrics. The binary serves HTTP during
optional startup checks, becomes ready after initialization, and clears readiness on shutdown.
It supervises HTTP, startup, and collector tasks and exits on unexpected task termination.

`/health` is healthy only when every router has a complete successful collection no older than
`3 × collection interval` and fewer than three consecutive errors for that router's exact
connection identity (address, username, password, and TLS settings). The freshness window is
independent of `GAP_RESET_THRESHOLD_SECONDS`, which only controls counter-baseline resets, so a
large gap-reset value cannot mask a stale router. Empty configuration or no complete success is
degraded. Use the group metrics for detailed collection failures; `/health` is not a replacement
for them.

## Collection Semantics

Each router has a non-overlapping schedule with missed ticks skipped. A slow router does not
block another router's schedule. The metric groups are `system_interfaces`, `conntrack`,
`wireguard`, `certificates`, and `firewall`.

Only a **complete** collection advances router success/freshness. Partial snapshots increment
scrape errors while usable groups can still update. Group success means usable data; group
completeness means the entire group succeeded (including a valid empty result). Invalid required
numeric fields fail the affected fetch; invalid snapshots are rejected before updating metrics,
rather than converted to plausible zeroes. Previously collected values can remain during failures,
so always assess freshness alongside data.

A critical system/interfaces failure or an invalid numeric snapshot rejects the overall production
collection, marking all groups failed for that attempt. The public registry update methods expect
already validated input; library callers must uphold that contract when supplying snapshots directly.

Interface and firewall counters accumulate router deltas and handle router resets. The first
sample after startup seeds the counter with the router's cumulative value; a label that appears
later (new or returning) starts at zero and accumulates deltas, and after collection errors or a
long gap the baseline is reset, so recovery never produces a spike. Firewall baselines retained
during partial snapshots keep their TTL refreshed. WireGuard byte metrics remain gauges of router
totals, not Prometheus counters.

Dynamic labels are cleaned periodically with a 30-minute TTL. Replaced `system_info` labels are
set to zero and later expire; use `mikrotik_system_info == 1` in metadata joins. Conntrack retains
at most **1024 series per router**, including retained partial-snapshot series, in deterministic
`(ip_version, src_address, protocol)` order. `mikrotik_conntrack_dropped_series` counts distinct
series observed in the latest usable snapshot that the cap omitted; it excludes retained series
carried over from earlier partial snapshots and is a gauge, not a lifetime counter.

## Full Metrics List

### Interfaces

Labels: `router,id`; `mikrotik_interface_info` additionally has `name,comment`.

| Metric | Type | Meaning |
| --- | --- | --- |
| `mikrotik_interface_rx_bytes_total`, `mikrotik_interface_tx_bytes_total` | counter | Traffic bytes |
| `mikrotik_interface_rx_packets_total`, `mikrotik_interface_tx_packets_total` | counter | Packets |
| `mikrotik_interface_rx_errors_total`, `mikrotik_interface_tx_errors_total` | counter | Errors |
| `mikrotik_interface_running` | gauge | 1 running, 0 stopped |
| `mikrotik_interface_info` | gauge | Metadata, 1 current |

RouterOS omits `rx-error`/`tx-error` for some interface types. When they are absent the error
counters are left unchanged rather than forced to zero, so their series may be absent until the
router first reports them. `InterfaceStats::rx_errors` and `tx_errors` are `Option<u64>`.

### System

Labels: `router`; only `mikrotik_system_info` additionally has `version,board`.

| Metric | Type | Meaning |
| --- | --- | --- |
| `mikrotik_system_cpu_load_ratio` | gauge | CPU utilization 0–1; multiply by 100 for percent |
| `mikrotik_system_free_memory_bytes`, `mikrotik_system_total_memory_bytes` | gauge | Memory bytes |
| `mikrotik_system_uptime_seconds` | gauge | Uptime seconds |
| `mikrotik_system_info` | gauge | Metadata, 1 current, 0 superseded |

### Collection and Pool

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `mikrotik_scrape_success_total` | counter | `router` | Complete successful collections |
| `mikrotik_scrape_errors_total` | counter | `router` | Failed or incomplete collections |
| `mikrotik_scrape_duration_seconds` | gauge | `router` | Last collection duration |
| `mikrotik_scrape_last_success_timestamp_seconds` | gauge | `router` | Last complete success Unix time; 0 never |
| `mikrotik_connection_consecutive_errors` | gauge | `router` | Maximum consecutive errors across router pool groups |
| `mikrotik_group_collection_success` | gauge | `router,group` | Last group fetch has usable data, 1/0 |
| `mikrotik_group_collection_complete` | gauge | `router,group` | Last group fetch is complete, 1/0 |
| `mikrotik_group_last_success_timestamp_seconds` | gauge | `router,group` | Last complete group Unix time; 0 never |
| `mikrotik_collection_cycle_duration_seconds` | gauge | none | Time for every router to finish at least once since the previous aggregate cycle |
| `mikrotik_connection_pool_size` | gauge | none | Total pooled connections |
| `mikrotik_connection_pool_active` | gauge | none | Active connections |

Configured router service/group/conntrack-observability families are initialized at zero before
the first collection. Entity data families appear when data is available.

### Connection Tracking

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `mikrotik_connection_tracking_count` | gauge | `router,src_address,protocol,ip_version` | Connections per source/protocol/IP version |
| `mikrotik_conntrack_active_series` | gauge | `router` | Retained series |
| `mikrotik_conntrack_dropped_series` | gauge | `router` | Latest usable snapshot series omitted by the cap |
| `mikrotik_conntrack_update_duration_seconds` | gauge | `router` | Last registry conntrack update duration |

### WireGuard and Certificates

WireGuard data labels: `router,id`. Peer info additionally has
`interface,name,allowed_address,endpoint,comment`. Certificate labels: `router,id,name`.

| Metric | Type | Meaning |
| --- | --- | --- |
| `mikrotik_wireguard_peer_rx_bytes`, `mikrotik_wireguard_peer_tx_bytes` | gauge | Router byte totals |
| `mikrotik_wireguard_peer_latest_handshake_timestamp_seconds` | gauge | Last handshake Unix time; 0 when absent |
| `mikrotik_wireguard_peer_info` | gauge | Peer metadata |
| `mikrotik_certificate_days_until_expiry` | gauge | Days until expiry; negative means expired |

### Firewall

Counter labels: `router,id,chain,action,ip_version,section`.
Info labels: `router,id,ip_version,section,comment`.

| Metric | Type | Meaning |
| --- | --- | --- |
| `mikrotik_firewall_rule_bytes_total`, `mikrotik_firewall_rule_packets_total` | counter | Rule traffic |
| `mikrotik_firewall_rule_info` | gauge | Rule metadata |

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete local gate, commit conventions, and releases.
Ordinary tests use fixtures and loopback servers; they never opt into real-device tests just
because credentials exist in the environment.

```bash
cargo test --all-features --locked
cargo test --doc --all-features --locked
```

Only with explicit permission and a configured test router:

```bash
cargo test --all-features --locked --test integration_tests test_real_router_connectivity -- --ignored --exact
```

## Project Architecture

- `src/config/`: fallible environment/JSON loading and validation.
- `src/mikrotik/connection/`: bounded RouterOS framing, authentication, and TLS transport.
- `src/mikrotik/pool/`: group-aware connection reuse, backoff, and cancellation safety.
- `src/mikrotik/client/groups/` and `src/mikrotik/responses/`: fetch and parse metric groups.
- `src/collector/`: independent schedules, snapshot application, cleanup, and worker supervision.
- `src/metrics/registry/`: registration, deltas, freshness, cardinality limits, and cleanup.
- `src/api/`: cached metrics and process/router status endpoints.
- `src/main.rs`: startup, task supervision, readiness, and bounded shutdown.

### Using as a Library

The [crate documentation](https://docs.rs/mikrotik-exporter) documents published versions;
`cargo doc --no-deps --open` renders the current source. `Config::from_env()` returns `Result<Config>`.
`start_collection_loop` returns `JoinHandle<Result<()>>`: retain and supervise it, signal shutdown,
and await it to observe both collection and task errors. The compile-checked example in
[`src/lib.rs`](src/lib.rs) shows this lifecycle without running a network doctest.

`create_router` assumes initialization is already complete and uses fixed ready status. For
lifecycle-aware embedding, use `Arc<AppState>::router_with_readiness` with a watch receiver.
See `src/main.rs` for HTTP serving, startup checks, and shutdown integration.

## Grafana and License

Import [`grafana/dashboard.json`](grafana/dashboard.json) matching this source tree. The
[catalog dashboard 24875](https://grafana.com/grafana/dashboards/24875-mikrotik-router-monitoring/)
may lag unreleased metric migrations.

MIT — see [LICENSE](LICENSE).
