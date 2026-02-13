// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Per-router collection task

use crate::config::RouterConfig;
use crate::metrics::{InterfaceLabels, MetricsRegistry, RouterLabels};
use crate::mikrotik::{ConnectionPool, MikroTikClient};
use std::collections::HashSet;
use std::sync::Arc;

use super::cache::SystemInfoCache;

pub(super) fn spawn_router_collection(
    router: RouterConfig,
    pool: Arc<ConnectionPool>,
    metrics: MetricsRegistry,
    system_cache: SystemInfoCache,
    active_interfaces: Arc<tokio::sync::Mutex<HashSet<InterfaceLabels>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let router_name = router.name.clone();
        let client = MikroTikClient::with_pool(router.clone(), pool.clone());
        let router_label = RouterLabels {
            router: router_name.clone(),
        };

        tracing::trace!("Starting metrics collection for router: {}", router_name);
        let start = std::time::Instant::now();
        match client.collect_metrics().await {
            Ok(m) => {
                let duration = start.elapsed().as_secs_f64();

                // Track active interfaces
                {
                    let mut active = active_interfaces.lock().await;
                    for iface in &m.interfaces {
                        active.insert(InterfaceLabels {
                            router: router_name.clone(),
                            interface: iface.name.clone(),
                        });
                    }
                }

                metrics.update_metrics(&m).await;
                metrics.record_scrape_success(&router_label);
                metrics.record_scrape_duration(&router_label, duration);

                // Cache system info if it's the first time
                if system_cache.get(&router_name).await.is_none() {
                    system_cache
                        .set(router_name.clone(), m.system.clone())
                        .await;
                }

                // Update connection error count
                if let Some((errors, _)) = pool
                    .get_connection_state(&router.address, &router.username)
                    .await
                {
                    metrics.update_connection_errors(&router_label, errors);
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
                metrics.record_scrape_error(&router_label);
                metrics.record_scrape_duration(&router_label, duration);

                // Update connection error count
                if let Some((errors, _)) = pool
                    .get_connection_state(&router.address, &router.username)
                    .await
                {
                    metrics.update_connection_errors(&router_label, errors);
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
    })
}
