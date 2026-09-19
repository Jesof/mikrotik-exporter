// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! # `MikroTik` Exporter
//!
//! Prometheus exporter for `MikroTik` `RouterOS` devices.
//!
//! This library provides functionality to collect metrics from `MikroTik` routers
//! via the `RouterOS` API and expose them in Prometheus format.
//!
//! ## Installation
//!
//! To use the published 0.5 line, add it to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! mikrotik-exporter = "0.5"
//! ```
//!
//! Documentation built from the current checkout may include unreleased changes. The collector
//! lifecycle below targets this checkout; consult the changelog when migrating from an earlier
//! released version. Use a path dependency for local development against this source tree.
//!
//! To install the exporter as a binary, use cargo:
//!
//! ```bash
//! cargo install mikrotik-exporter
//! ```
//!
//! ## Grafana Dashboard
//!
//! A pre-configured Grafana dashboard is available:
//! - **ID:** `24875`
//! - **URL:** [Grafana Dashboard #24875](https://grafana.com/grafana/dashboards/24875-mikrotik-router-monitoring/)
//!
//! ## Features
//!
//! - **Multi-router support**: Collect metrics from multiple `MikroTik` devices
//! - **Asynchronous architecture**: Efficient concurrent collection using connection pooling
//! - **Comprehensive metrics**: Interface statistics, system resources, connection tracking, `WireGuard`
//! - **Built-in connection pooling**: Automatic connection management with exponential backoff
//! - **Delta calculation**: Automatic counter delta calculation for accurate rate metrics
//! - **Startup connectivity testing**: Optional connectivity verification during application startup
//! - **Verified TLS**: Optional per-router API-SSL with system roots or a custom CA bundle
//! - **Health checking**: Process probes and cached router/group freshness diagnostics
//!
//! ## Collector Lifecycle
//!
//! This compile-checked example does not run during doctests. Running it explicitly contacts the
//! configured routers. The binary in `src/main.rs` also supervises HTTP serving and startup checks,
//! manages readiness, and handles platform shutdown signals.
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//! use tokio::sync::watch;
//! use mikrotik_exporter::{
//!     AppError, Config, ConnectionPool, MetricsRegistry, Result,
//!     start_collection_loop,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let config = Config::from_env()?;
//!     let metrics = MetricsRegistry::new();
//!     let pool = Arc::new(ConnectionPool::new());
//!     let (shutdown_tx, shutdown_rx) = watch::channel(false);
//!     let mut collector = start_collection_loop(shutdown_rx, Arc::new(config), metrics, pool);
//!     let signal_result = tokio::select! {
//!         result = &mut collector => {
//!             result.map_err(|error| AppError::Io(std::io::Error::other(error)))??;
//!             return Err(AppError::Io(std::io::Error::other("collector stopped unexpectedly")));
//!         }
//!         result = tokio::signal::ctrl_c() => result,
//!     };
//!     shutdown_tx.send_replace(true);
//!     match tokio::time::timeout(Duration::from_secs(5), &mut collector).await {
//!         Ok(result) => result.map_err(|error| AppError::Io(std::io::Error::other(error)))??,
//!         Err(_) => {
//!             collector.abort();
//!             let _ = collector.await;
//!             return Err(AppError::Io(std::io::Error::other("collector shutdown timed out")));
//!         }
//!     }
//!     signal_result.map_err(AppError::Io)
//! }
//! ```
//!
//! ## Configuration
//!
//! [`Config::from_env`] returns [`Result<Config>`] and rejects invalid settings and duplicate
//! router names. Call [`Config::validate`] for programmatically constructed configurations.
//! Library callers can load dotenv explicitly before reading configuration; the binary does so.
//! [`RouterConfig::tls`] selects verified TLS when present, even as an empty object in JSON;
//! omission or `null` selects plaintext. [`RouterTlsConfig`] controls identity and trust roots.
//!
//! [`create_router`] assumes initialization is complete. Use [`AppState::router_with_readiness`]
//! to control `/ready` via a watch receiver; `/live` is independent of router availability and
//! `/health` reports cached diagnostics. Neither `/metrics` nor `/health` initiates router I/O.
//!
//! ## Main modules
//! - `api`: HTTP API handlers
//! - `collector`: metrics collection and processing
//! - `config`: configuration management
//! - `error`: error types
//! - `metrics`: metrics parsing and registry
//! - `mikrotik`: `MikroTik` device interaction
//! - `prelude`: commonly used types and traits
//!
//! ## Performance Optimizations
//!
//! - **DashMap-based bookkeeping**: Sharded concurrent maps for metric state
//! - **Efficient delta calculations**: Minimal overhead for counter metric processing
//! - **Connection pooling**: Reuse connections to reduce authentication overhead
//! - **Bounded cardinality**: Conntrack retained-series cap and periodic stale-label cleanup

mod api;
mod collector;
mod config;
mod error;
mod metrics;
mod mikrotik;
pub mod prelude;
mod startup;

// Re-export commonly used types
/// Application configuration
pub use config::{Config, ConfigError, RouterConfig, RouterError, RouterTlsConfig, TlsError};

/// Application error and result type
pub use error::{AppError, Result};

/// HTTP API router and state
pub use api::{AppState, create_router};

/// Metrics collection loop
pub use collector::start_collection_loop;

/// Startup connectivity policy and checks
pub use startup::run_startup_connectivity_tests;

/// Metrics registry and labels
pub use metrics::{MetricsRegistry, RouterLabels};

/// `MikroTik` connection pool and metric input types
pub use mikrotik::{
    CertificateStats, CollectionStatus, CollectionStatusParts, ConnectionPool,
    ConnectionTrackingStats, FetchState, FirewallRuleStats, InterfaceStats, ProtocolError,
    RouterMetrics, SnapshotError, SystemResource, WireGuardPeerStats,
};
