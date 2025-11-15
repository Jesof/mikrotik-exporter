//! Metrics collection orchestration
//!
//! This module manages the background collection of metrics from MikroTik routers.

use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::api::AppState;
use crate::metrics::RouterLabels;
use crate::mikrotik::{ConnectionPool, MikroTikClient};

/// Starts the background metrics collection loop
///
/// This function spawns a task that periodically collects metrics from all configured routers.
/// It also starts a cleanup task for the connection pool.
pub fn start_collection_loop(
    mut shutdown_rx: watch::Receiver<bool>,
    state: Arc<AppState>,
) -> JoinHandle<()> {
    let interval = state.config.collection_interval_secs;
    tracing::info!("Starting background collection loop every {}s", interval);

    // Create shared connection pool for all routers
    let pool = Arc::new(ConnectionPool::new());

    // Start cleanup task for expired connections
    start_pool_cleanup_task(pool.clone(), shutdown_rx.clone());

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
            for router in &state.config.routers {
                let client = MikroTikClient::with_pool(router.clone(), pool.clone());
                let metrics_ref = state.metrics.clone();
                let router_name = router.name.clone();
                let router_label = RouterLabels {
                    router: router_name.clone(),
                };
                let pool_ref = pool.clone();
                let router_config = router.clone();

                tokio::spawn(async move {
                    let start = std::time::Instant::now();
                    match client.collect_metrics().await {
                        Ok(m) => {
                            let duration = start.elapsed().as_secs_f64();
                            metrics_ref.update_metrics(&m).await;
                            metrics_ref.record_scrape_success(&router_label);
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

                            tracing::debug!(
                                "Collected metrics for router {} in {:.3}s",
                                router_name,
                                duration
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
                        }
                    }
                });
            }

            // Update pool statistics after all routers processed
            let (total, active) = pool.get_pool_stats().await;
            state.metrics.update_pool_stats(total, active);
        }
    })
}

/// Starts a background task to clean up expired connections
fn start_pool_cleanup_task(pool: Arc<ConnectionPool>, mut shutdown_rx: watch::Receiver<bool>) {
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
