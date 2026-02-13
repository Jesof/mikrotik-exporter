// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! # MikroTik Exporter
//!
//! Prometheus exporter for MikroTik RouterOS devices.
//!
//! This library provides functionality to collect metrics from MikroTik routers
//! via the RouterOS API and expose them in Prometheus format.
//!
//! ## Main modules
//! - `api`: HTTP API handlers
//! - `collector`: metrics collection and processing
//! - `config`: configuration management
//! - `error`: error types
//! - `metrics`: metrics parsing and registry
//! - `mikrotik`: MikroTik device interaction
//! - `prelude`: commonly used types and traits

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
pub use mikrotik::{ConnectionPool, InterfaceStats, RouterMetrics, SystemResource};

/// RouterOS wire protocol length encoding (public for tests)
pub use mikrotik::encode_length;
