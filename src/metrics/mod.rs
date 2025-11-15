//! Metrics registry and update logic.

mod labels;
mod parsers;
mod registry;

#[cfg(test)]
mod tests;

// Re-export public types
pub use labels::{InterfaceLabels, RouterLabels, SystemInfoLabels};
pub use registry::MetricsRegistry;
