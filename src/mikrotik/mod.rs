// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! RouterOS API client module for MikroTik
//!
//! Implements connection to MikroTik routers via RouterOS API,
//! authentication, and collection of metrics including system resources,
//! interfaces, connection tracking, WireGuard, and certificates.

mod client;
mod connection;
mod pool;
mod responses;
pub(crate) mod types;

/// Client for MikroTik RouterOS API
pub(crate) use client::MikroTikClient;

/// Connection pool for routers
pub use pool::ConnectionPool;

/// Types for router metrics and statistics
pub use types::{
    CertificateStats, ConnectionTrackingStats, InterfaceStats, RouterMetrics, SystemResource,
    WireGuardInterfaceStats, WireGuardPeerStats,
};

pub use connection::encode_length;
