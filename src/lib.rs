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

pub mod api;
pub mod collector;
pub mod config;
pub mod error;
pub mod metrics;
pub mod mikrotik;
pub mod prelude;

// Re-export commonly used types
/// Application configuration
pub use config::Config;

/// Application error and result type
pub use error::{AppError, Result};
