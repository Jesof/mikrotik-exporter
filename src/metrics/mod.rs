// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Metrics registry and update module for MikroTik Exporter
//!
//! Contains types for labels, parsers, and Prometheus metrics registry.

pub(crate) mod labels;
mod parsers;
mod registry;

#[cfg(test)]
mod tests;

/// Labels for router-level metrics
pub use labels::RouterLabels;

/// Prometheus metrics registry
pub use registry::MetricsRegistry;
