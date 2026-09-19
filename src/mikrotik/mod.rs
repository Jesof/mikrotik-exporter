// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! `RouterOS` API client module for `MikroTik`
//!
//! Implements connection to `MikroTik` routers via `RouterOS` API,
//! authentication, and collection of metrics including system resources,
//! interfaces, connection tracking, `WireGuard`, and certificates.

mod client;
mod connection;
mod error;
mod pool;
mod responses;
pub(crate) mod types;

pub use error::{ProtocolError, SnapshotError};

/// Client for `MikroTik` `RouterOS` API
pub(crate) use client::MikroTikClient;

/// Connection pool for routers
pub use pool::ConnectionPool;

/// Types for router metrics and statistics
pub use types::{
    CertificateStats, CollectionStatus, CollectionStatusParts, ConnectionTrackingStats, FetchState,
    FirewallRuleStats, InterfaceStats, RouterMetrics, SystemResource, WireGuardPeerStats,
};
