//! Metrics registry and update module for MikroTik Exporter
//!
//! Contains types for labels, parsers, and Prometheus metrics registry.

mod labels;
mod parsers;
mod registry;

#[cfg(test)]
mod tests;

/// Labels for interfaces, routers, and system info
pub use labels::{InterfaceLabels, RouterLabels, SystemInfoLabels};

/// Prometheus metrics registry
pub use registry::MetricsRegistry;
