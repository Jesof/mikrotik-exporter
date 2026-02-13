// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! RouterOS API client module for MikroTik
//!
//! Implements connection to MikroTik routers via RouterOS API,
//! authentication, and collection of system/interface metrics.

mod client;
mod connection;
mod pool;
pub(crate) mod types;
pub(crate) mod wireguard;

/// Client for MikroTik RouterOS API
pub(crate) use client::MikroTikClient;

/// Connection pool for routers
pub use pool::ConnectionPool;

/// Types for router metrics and statistics
pub use types::{ConnectionTrackingStats, InterfaceStats, RouterMetrics, SystemResource};

/// Types for WireGuard metrics and statistics
pub use wireguard::{WireGuardInterfaceStats, WireGuardPeerStats};

pub use connection::encode_length;
