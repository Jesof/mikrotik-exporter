//! MikroTik Exporter - Prometheus exporter for MikroTik RouterOS devices
//!
//! This library provides functionality to collect metrics from MikroTik routers
//! via the RouterOS API and expose them in Prometheus format.

pub mod api;
pub mod collector;
pub mod config;
pub mod error;
pub mod metrics;
pub mod mikrotik;
pub mod prelude;

// Re-export commonly used types
pub use config::Config;
pub use error::{AppError, Result};
