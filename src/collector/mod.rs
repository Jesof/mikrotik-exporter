// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Metrics collection orchestration module for MikroTik routers
//!
//! Starts background metrics collection, manages connection pool and cleanup.

mod cache;
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

use self::cache::SystemInfoCache;
use self::router_task::spawn_router_collection;

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

    // Create system info cache for immutable metrics
    let system_cache = SystemInfoCache::new();

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
    const CLEANUP_EVERY_N_CYCLES: u64 = 20;
    const STALE_LABEL_TTL: Duration = Duration::from_secs(60 * 30);

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

            // Track active interfaces for cleanup
            let active_interfaces = Arc::new(tokio::sync::Mutex::new(HashSet::new()));

            // Collect metrics from all routers
            let mut tasks = Vec::new();
            for router in &config.routers {
                let task = spawn_router_collection(
                    router.clone(),
                    pool.clone(),
                    metrics.clone(),
                    system_cache.clone(),
                    active_interfaces.clone(),
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

            // Periodic cleanup of stale interface metrics
            collection_cycle += 1;
            if collection_cycle % CLEANUP_EVERY_N_CYCLES == 0 {
                let active_ifaces = active_interfaces.lock().await;
                metrics.cleanup_stale_interfaces(&active_ifaces).await;
                metrics
                    .cleanup_expired_dynamic_labels(STALE_LABEL_TTL)
                    .await;
                metrics.cleanup_stale_routers(&active_routers).await;
                system_cache.cleanup_stale(&active_routers).await;
                pool.cleanup_states(&active_pool_keys).await;
                tracing::debug!(
                    "Cleanup cycle {} completed (tracked {} active interfaces)",
                    collection_cycle,
                    active_ifaces.len()
                );
            }
        }
    })
}
