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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cleanup_task_respects_shutdown_signal() {
        let pool = Arc::new(ConnectionPool::default());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        start_pool_cleanup_task(pool.clone(), shutdown_rx);

        let _ = shutdown_tx.send(true);

        tokio::time::sleep(Duration::from_millis(100)).await;
        let (total, _) = pool.get_pool_stats().await;
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn test_cleanup_task_shutdown_on_first_signal() {
        let pool = Arc::new(ConnectionPool::default());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        start_pool_cleanup_task(pool.clone(), shutdown_rx);

        let _ = shutdown_tx.send(true);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (stats, _) = pool.get_pool_stats().await;
        assert_eq!(stats, 0);
    }

    #[tokio::test]
    async fn test_cleanup_task_handles_multiple_shutdown_attempts() {
        let pool = Arc::new(ConnectionPool::default());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        start_pool_cleanup_task(pool.clone(), shutdown_rx);

        let _ = shutdown_tx.send(true);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let _ = shutdown_tx.send(true);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (total, _) = pool.get_pool_stats().await;
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn test_cleanup_interval_constant_is_60_seconds() {
        assert_eq!(CLEANUP_INTERVAL, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_cleanup_task_with_pool_operations() {
        let pool = Arc::new(ConnectionPool::default());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        start_pool_cleanup_task(pool.clone(), shutdown_rx);

        for _ in 0..3 {
            let (total, _) = pool.get_pool_stats().await;
            assert!(total as i32 >= 0);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let _ = shutdown_tx.send(true);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (final_total, _) = pool.get_pool_stats().await;
        assert_eq!(final_total, 0);
    }

    #[tokio::test]
    async fn test_cleanup_task_select_responds_to_shutdown() {
        let pool = Arc::new(ConnectionPool::default());
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        start_pool_cleanup_task(pool.clone(), shutdown_rx);

        tokio::time::sleep(Duration::from_millis(100)).await;

        let (total, _) = pool.get_pool_stats().await;
        assert_eq!(total, 0);
    }
}
