//! Connection pool cleanup task
//!
//! This module provides internal functionality for cleaning up expired connections
//! from the connection pool. It's not part of the public API.

use std::sync::Arc;
use tokio::sync::watch;

use crate::mikrotik::ConnectionPool;

/// Starts a background task to clean up expired connections
///
/// This is an internal function (pub(super)) used only by the collector module
/// to manage connection lifecycle. It runs every 60 seconds.
pub(super) fn start_pool_cleanup_task(
    pool: Arc<ConnectionPool>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut cleanup_ticker = tokio::time::interval(std::time::Duration::from_secs(60));
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
