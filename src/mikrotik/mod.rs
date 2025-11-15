//! `MikroTik` `RouterOS` API client module
//!
//! This module provides functionality to connect to `MikroTik` routers via the `RouterOS` API,
//! authenticate, and collect system and interface metrics.

mod client;
mod connection;
mod pool;
mod types;

// Re-export public types and functions
pub use client::MikroTikClient;
pub use pool::ConnectionPool;
pub use types::{InterfaceStats, RouterMetrics, SystemResource};
