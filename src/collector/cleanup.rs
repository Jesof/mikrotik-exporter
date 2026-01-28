// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Connection pool cleanup task
//!
//! This module provides internal functionality for cleaning up expired connections
//! from the connection pool. It's not part of the public API.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

use crate::mikrotik::ConnectionPool;

/// Cleanup interval for expired connections (60 seconds)
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Starts a background task to clean up expired connections
///
/// This is an internal function (pub(super)) used only by the collector module
/// to manage connection lifecycle. It runs every 60 seconds.
pub(super) fn start_pool_cleanup_task(
    pool: Arc<ConnectionPool>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut cleanup_ticker = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            tokio::select! {
                _ = cleanup_ticker.tick() => {
                    pool.cleanup().await;
                },
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::debug!("Stopping connection pool cleanup");
                        break;
                    }
                }
            }
        }
    });
}
