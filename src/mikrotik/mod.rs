// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! RouterOS API client module for MikroTik
//!
//! Implements connection to MikroTik routers via RouterOS API,
//! authentication, and collection of system/interface metrics.

mod client;
mod connection;
mod pool;
mod types;

/// Client for MikroTik RouterOS API
pub use client::MikroTikClient;

/// Connection pool for routers
pub use pool::ConnectionPool;

/// Types for router metrics and statistics
pub use types::{InterfaceStats, RouterMetrics, SystemResource};
