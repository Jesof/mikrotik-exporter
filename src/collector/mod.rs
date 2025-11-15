//! Metrics collection orchestration module for MikroTik routers
//!
//! Starts background metrics collection, manages connection pool and cleanup.

mod cleanup;

use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::metrics::{MetricsRegistry, RouterLabels};
use crate::mikrotik::{ConnectionPool, MikroTikClient};

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

    // Start cleanup task for expired connections
    cleanup::start_pool_cleanup_task(pool.clone(), shutdown_rx.clone());

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
            metrics.update_pool_stats(total, active);
        }
    })
}
