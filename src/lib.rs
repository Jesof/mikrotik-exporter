// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! # MikroTik Exporter
//!
//! Prometheus exporter for MikroTik RouterOS devices.
//!
//! This library provides functionality to collect metrics from MikroTik routers
//! via the RouterOS API and expose them in Prometheus format.
//!
//! ## Installation
//!
//! To use this library in your project, add it to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! mikrotik-exporter = "0.2"
//! ```
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
//! - **Multi-router support**: Collect metrics from multiple MikroTik devices
//! - **Asynchronous architecture**: Efficient concurrent collection using connection pooling
//! - **Comprehensive metrics**: Interface statistics, system resources, connection tracking, WireGuard
//! - **Built-in connection pooling**: Automatic connection management with exponential backoff
//! - **Delta calculation**: Automatic counter delta calculation for accurate rate metrics
//! - **Startup connectivity testing**: Optional connectivity verification during application startup
//! - **Health checking**: Built-in health endpoint with router status monitoring
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use tokio::sync::watch;
//! use mikrotik_exporter::{
//!     AppState, Config, ConnectionPool, MetricsRegistry, Result, create_router,
//!     start_collection_loop,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let config = Config::from_env();
//!     let metrics = MetricsRegistry::new();
//!     let pool = Arc::new(ConnectionPool::new());
//!     let state = Arc::new(AppState {
//!         config: config.clone(),
//!         metrics: metrics.clone(),
//!         pool: pool.clone(),
//!     });
//!
//!     let (_shutdown_tx, shutdown_rx) = watch::channel(false);
//!     start_collection_loop(shutdown_rx, Arc::new(config), metrics, pool);
//!
//!     let app = create_router(state);
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:9090").await?;
//!     axum::serve(listener, app.into_make_service()).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Configuration
//!
//! Configuration can be loaded from environment variables using `Config::from_env()`.
//! See `Config` documentation for available options including startup connectivity testing.
//!
//! ## Main modules
//! - `api`: HTTP API handlers
//! - `collector`: metrics collection and processing
//! - `config`: configuration management
//! - `error`: error types
//! - `metrics`: metrics parsing and registry
//! - `mikrotik`: MikroTik device interaction
//! - `prelude`: commonly used types and traits
//!
//! ## Performance Optimizations
//!
//! - **DashMap-based metrics registry**: Lock-free concurrent access for better performance
//! - **Efficient delta calculations**: Minimal overhead for counter metric processing
//! - **Connection pooling**: Reuse connections to reduce authentication overhead
//! - **Incremental cleanup**: Periodic cleanup of stale metrics to prevent memory growth

mod api;
mod collector;
mod config;
mod error;
mod metrics;
mod mikrotik;
pub mod prelude;

// Re-export commonly used types
/// Application configuration
pub use config::{Config, RouterConfig};

/// Application error and result type
pub use error::{AppError, Result};

/// HTTP API router and state
pub use api::{AppState, create_router};

/// Metrics collection loop
pub use collector::start_collection_loop;

/// Metrics registry and labels
pub use metrics::{MetricsRegistry, RouterLabels};

/// MikroTik connection pool and metric input types
pub use mikrotik::{
    ConnectionPool, ConnectionTrackingStats, InterfaceStats, RouterMetrics, SystemResource,
    WireGuardInterfaceStats, WireGuardPeerStats,
};

/// RouterOS wire protocol length encoding (public for tests)
pub use mikrotik::encode_length;
