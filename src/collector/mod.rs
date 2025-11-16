// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Metrics collection orchestration module for MikroTik routers
//!
//! Starts background metrics collection, manages connection pool and cleanup.

mod cleanup;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::metrics::{MetricsRegistry, RouterLabels};
use crate::mikrotik::{ConnectionPool, MikroTikClient, SystemResource};

/// Cache for immutable system information (version, board name)
#[derive(Clone, Default)]
pub struct SystemInfoCache {
    cache: Arc<RwLock<HashMap<String, SystemResource>>>,
}

impl SystemInfoCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get(&self, router_name: &str) -> Option<SystemResource> {
        let cache = self.cache.read().await;
        cache.get(router_name).cloned()
    }

    pub async fn set(&self, router_name: String, system: SystemResource) {
        let mut cache = self.cache.write().await;
        tracing::debug!("Cached system info for router: {}", router_name);
        cache.insert(router_name, system);
    }
}

/// Starts the background metrics collection loop
///
/// Periodically collects metrics from all configured MikroTik routers.
/// Also starts the connection pool cleanup task.
pub fn start_collection_loop(
    mut shutdown_rx: watch::Receiver<bool>,
    config: Arc<Config>,
    metrics: MetricsRegistry,
) -> JoinHandle<()> {
    let interval = config.collection_interval_secs;
    tracing::info!("Starting background collection loop every {}s", interval);

    // Create shared connection pool for all routers
    let pool = Arc::new(ConnectionPool::new());

    // Create system info cache for immutable metrics
    let system_cache = SystemInfoCache::new();

    // Start cleanup task for expired connections
    cleanup::start_pool_cleanup_task(pool.clone(), shutdown_rx.clone());

    tracing::trace!(
        "Collection loop initialized with {} routers",
        config.routers.len()
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval));
        loop {
            tokio::select! {
                _ = ticker.tick() => {},
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Stopping collection loop");
                        break;
                    }
                }
            }

            // Collect metrics from all routers
            for router in &config.routers {
                let client = MikroTikClient::with_pool(router.clone(), pool.clone());
                let metrics_ref = metrics.clone();
                let router_name = router.name.clone();
                let router_label = RouterLabels {
                    router: router_name.clone(),
                };
                let pool_ref = pool.clone();
                let router_config = router.clone();
                let cache_ref = system_cache.clone();

                tokio::spawn(async move {
                    tracing::trace!("Starting metrics collection for router: {}", router_name);
                    let start = std::time::Instant::now();
                    match client.collect_metrics().await {
                        Ok(m) => {
                            let duration = start.elapsed().as_secs_f64();
                            metrics_ref.update_metrics(&m).await;
                            metrics_ref.record_scrape_success(&router_label);
                            metrics_ref.record_scrape_duration(&router_label, duration);

                            // Cache system info if it's the first time or if it changed
                            if cache_ref.get(&router_name).await.is_none() {
                                cache_ref.set(router_name.clone(), m.system.clone()).await;
                            }

                            // Update connection error count
                            if let Some((errors, _)) = pool_ref
                                .get_connection_state(
                                    &router_config.address,
                                    &router_config.username,
                                )
                                .await
                            {
                                metrics_ref.update_connection_errors(&router_label, errors);
                            }

                            tracing::debug!(
                                "Collected metrics for router {} in {:.3}s",
                                router_name,
                                duration
                            );
                            tracing::trace!(
                                "Router {} metrics: {} interfaces, CPU: {}%, Memory: {}/{} bytes",
                                router_name,
                                m.interfaces.len(),
                                m.system.cpu_load,
                                m.system.free_memory,
                                m.system.total_memory
                            );
                        }
                        Err(e) => {
                            let duration = start.elapsed().as_secs_f64();
                            metrics_ref.record_scrape_error(&router_label);
                            metrics_ref.record_scrape_duration(&router_label, duration);

                            // Update connection error count
                            if let Some((errors, _)) = pool_ref
                                .get_connection_state(
                                    &router_config.address,
                                    &router_config.username,
                                )
                                .await
                            {
                                metrics_ref.update_connection_errors(&router_label, errors);
                            }

                            tracing::warn!(
                                "Failed to collect metrics for {} in {:.3}s: {}",
                                router_name,
                                duration,
                                e
                            );
                            tracing::trace!("Error details for {}: {:?}", router_name, e);
                        }
                    }
                });
            }

            // Update pool statistics after all routers processed
            let (total, active) = pool.get_pool_stats().await;
            metrics.update_pool_stats(total, active);
        }
    })
}
