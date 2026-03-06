// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Per-router collection task
//!
//! # Purpose
//!
//! This module implements the per-router metrics collection logic that runs concurrently
//! for each configured router in the background.
//!
//! ## Collection Process
//!
//! 1. **Client Creation**: Creates a `MikroTikClient` with connection pool
//! 2. **Metrics Collection**: Calls `collect_metrics()` to gather all router data
//! 3. **Active Interface Tracking**: Records which interfaces are currently active
//! 4. **Metrics Update**: Updates the shared `MetricsRegistry` with new values
//! 5. **Scrape Recording**: Records success/failure and duration for monitoring
//! 6. **Error Tracking**: Updates connection error count for health monitoring
//!
//! ## Concurrency Model
//!
//! - Each router runs in its own `tokio::spawn` task
//! - Tasks run concurrently without blocking each other
//! - Shared state (`MetricsRegistry`, `ConnectionPool`) is `Arc` for thread safety
//! - Active interface tracking uses `Mutex<HashSet>` for safe concurrent updates
//!
//! ## Error Handling
//!
//! - Collection errors are logged but don't stop the main loop
//! - Failed collections record scrape errors for monitoring
//! - Connection errors update consecutive error count for backoff
//! - Graceful degradation: one router failure doesn't affect others
//!
//! ## Performance Tracking
//!
//! - Records collection duration for each router
//! - Logs detailed metrics on success (interface count, CPU, memory)
//! - Logs warnings with error details on failure
//! - Trace-level logging for debugging with full error context

use crate::config::RouterConfig;
use crate::metrics::{MetricsRegistry, RouterLabels};
use crate::mikrotik::{ConnectionPool, MikroTikClient};
use std::sync::Arc;
use std::time::Duration;

pub(super) fn spawn_router_collection(
    router: RouterConfig,
    pool: Arc<ConnectionPool>,
    metrics: MetricsRegistry,
    gap_reset_threshold: Duration,
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
                let end = std::time::Instant::now();
                let duration = end.duration_since(start).as_secs_f64();

                // Sanity check: if router returned NO interfaces but we had them before,
                // it might be a transient RouterOS API glitch after reconnect.
                // We treat this as a "soft" error - we don't update metrics but we log it.
                if m.interfaces.is_empty() {
                    tracing::warn!(
                        "Router {} returned no interfaces; treating as collection failure to prevent stale metrics",
                        router_name
                    );
                    metrics.record_scrape_error(&router_label);
                    metrics.record_scrape_duration(&router_label, duration);
                    update_connection_error_metric(&metrics, pool.as_ref(), &router, &router_label)
                        .await;
                    return;
                }

                let gap = metrics.record_scrape_success_and_check_gap(
                    &router_label,
                    end.into(),
                    gap_reset_threshold,
                );
                if let Some(gap_duration) = gap {
                    tracing::info!(
                        "Resetting counter baselines for router {} after scrape gap of {:?}",
                        router_name,
                        gap_duration
                    );
                    metrics.update_metrics_baseline(&m);
                } else {
                    metrics.update_metrics(&m);
                }
                metrics.record_scrape_duration(&router_label, duration);
                update_connection_error_metric(&metrics, pool.as_ref(), &router, &router_label)
                    .await;

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
                update_connection_error_metric(&metrics, pool.as_ref(), &router, &router_label)
                    .await;

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

async fn update_connection_error_metric(
    metrics: &MetricsRegistry,
    pool: &ConnectionPool,
    router: &RouterConfig,
    router_label: &RouterLabels,
) {
    if let Some((errors, _)) = pool
        .get_connection_state(&router.address, &router.username, None)
        .await
    {
        metrics.update_connection_errors(router_label, errors);
    }
}
