// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Metrics collection orchestration module for `MikroTik` routers
//!
//! # Architecture
//!
//! This module implements the core metrics collection loop that runs in the background
//! to periodically collect metrics from all configured `MikroTik` routers.
//!
//! ## Components
//!
//! - **Main Collection Loop**: Manages the periodic collection schedule and spawns per-router tasks
//! - **Router Task** (`router_task`): Handles metrics collection for a single router
//! - **Cleanup** (`cleanup`): Periodic cleanup of stale connections and metrics
//!
//! ## Collection Flow
//!
//! 1. The main loop waits for the configured interval (default: 30 seconds)
//! 2. For each configured router, spawns a collection task using connection pooling
//! 3. All router tasks run concurrently using `tokio::spawn`
//! 4. After all tasks complete, updates pool statistics and records cycle duration
//! 5. Every 20 cycles (10 minutes by default), performs cleanup of:
//!    - Stale interface metrics for removed interfaces
//!    - Expired dynamic labels (30-minute TTL)
//!    - Inactive router metrics
//!    - Connection pool states for removed routers
//!
//! ## Connection Management
//!
//! Uses [`ConnectionPool`] for efficient connection reuse with exponential backoff
//! for failed connections. Connections are automatically returned to the pool via
//! RAII guards (`PooledConnectionGuard`).
//!
//! ## Graceful Shutdown
//!
//! The collection loop listens for shutdown signals via `watch::channel` and
//! gracefully stops collection, waiting for the cleanup task to complete.

mod cleanup;
mod router_task;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::metrics::{MetricsRegistry, RouterLabels};
use crate::mikrotik::ConnectionPool;

use self::router_task::spawn_router_collection;

const CLEANUP_EVERY_N_CYCLES: u64 = 20;
const STALE_LABEL_TTL: Duration = Duration::from_secs(60 * 30);
const MIN_GAP_RESET_SECS: u64 = 30;

/// Starts the background metrics collection loop
///
/// Spawns a background task that periodically collects metrics from all configured routers.
/// The collection interval is configurable via `Config::collection_interval_secs`.
///
/// Also starts the connection pool cleanup task.
pub fn start_collection_loop(
    mut shutdown_rx: watch::Receiver<bool>,
    config: Arc<Config>,
    metrics: MetricsRegistry,
    pool: Arc<ConnectionPool>,
) -> JoinHandle<()> {
    let interval = config.collection_interval_secs;
    tracing::info!("Starting background collection loop every {}s", interval);

    // Start cleanup task for expired connections (joined inside collection loop on shutdown)
    let cleanup_handle = cleanup::start_pool_cleanup_task(pool.clone(), shutdown_rx.clone());

    // Initialize metrics for all routers to ensure counters start at zero
    for router in &config.routers {
        let router_label = RouterLabels {
            router: router.name.clone(),
        };
        metrics.initialize_router_metrics(&router_label);
    }

    tracing::trace!(
        "Collection loop initialized with {} routers",
        config.routers.len()
    );

    // Cleanup interval: every 20 collection cycles
    let gap_reset_threshold = Duration::from_secs(config.gap_reset_threshold_secs)
        .max(Duration::from_secs(MIN_GAP_RESET_SECS));

    let active_routers: HashSet<String> = config
        .routers
        .iter()
        .map(|router| router.name.clone())
        .collect();
    let active_pool_keys: HashSet<String> = config
        .routers
        .iter()
        .map(|router| format!("{}:{}", router.address, router.username))
        .collect();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval));
        let mut collection_cycle: u64 = 0;

        loop {
            tokio::select! {
                _ = ticker.tick() => {},
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Stopping collection loop");
                        let _ = cleanup_handle.await;
                        break;
                    }
                }
            }

            let cycle_start = std::time::Instant::now();

            // Collect metrics from all routers
            let mut tasks = Vec::new();
            for router in &config.routers {
                let task = spawn_router_collection(
                    router.clone(),
                    pool.clone(),
                    metrics.clone(),
                    gap_reset_threshold,
                );
                tasks.push(task);
            }

            // Wait for all collection tasks to complete
            for task in tasks {
                let _ = task.await;
            }

            // Update pool statistics after all routers processed
            let (total, active) = pool.get_pool_stats().await;
            metrics.update_pool_stats(total, active);

            // Record full collection cycle duration
            metrics.record_collection_cycle_duration(cycle_start.elapsed().as_secs_f64());

            // Periodic cleanup
            collection_cycle += 1;
            if collection_cycle % CLEANUP_EVERY_N_CYCLES == 0 {
                metrics.cleanup_expired_dynamic_labels(STALE_LABEL_TTL);
                metrics.cleanup_stale_routers(&active_routers);
                pool.cleanup_states(&active_pool_keys).await;
                tracing::debug!("Cleanup cycle {} completed", collection_cycle,);
            }
        }
    })
}
