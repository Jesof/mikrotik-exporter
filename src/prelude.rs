// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Prelude module for convenient imports
//!
//! This module re-exports commonly used types and traits for convenient use.
//! Users of the library can import everything they need with:
//!
//! ```rust
//! use mikrotik_exporter::prelude::*;
//! ```

// Core types
pub use crate::config::{Config, RouterConfig};
pub use crate::error::{AppError, Result};

// Metrics types
pub use crate::metrics::{
    ConntrackLabels, InterfaceLabels, MetricsRegistry, RouterLabels, SystemInfoLabels,
    WireGuardInterfaceLabels, WireGuardPeerLabels,
};

// MikroTik client
pub use crate::mikrotik::{
    ConnectionPool, ConnectionTrackingStats, InterfaceStats, MikroTikClient, RouterMetrics,
    SystemResource, WireGuardInterfaceStats, WireGuardPeerStats,
};
