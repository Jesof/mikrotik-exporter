// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Production metrics collection loop.
//!
//! Schedules per-router collection on independent, non-overlapping tasks,
//! supervises the tasks, and performs periodic dynamic-label cleanup.

mod cleanup;
mod router_task;

use std::collections::HashSet;
use std::future::Future;
use std::io::Error as IoError;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior};

use crate::config::Config;
use crate::metrics::{MetricsRegistry, RouterLabels};
use crate::mikrotik::ConnectionPool;
use crate::prelude::{AppError, Result};

const STALE_LABEL_TTL: Duration = Duration::from_mins(30);

#[must_use]
/// Starts the supervised metrics collection loop.
///
/// Spawns one schedule task per router plus a pool-cleanup task, and returns
/// their `JoinHandle`. On shutdown the handle resolves once all tasks joined.
pub fn start_collection_loop(
    mut shutdown_rx: watch::Receiver<bool>,
    config: Arc<Config>,
    metrics: MetricsRegistry,
    pool: Arc<ConnectionPool>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        config.validate()?;
        if *shutdown_rx.borrow() || shutdown_rx.has_changed().is_err() {
            return Ok(());
        }
        let mut tasks = JoinSet::new();
        let (completed_tx, mut completed_rx) = mpsc::channel(config.routers.len().max(1));
        for router in &config.routers {
            metrics.initialize_router_metrics(&RouterLabels {
                router: router.name.clone(),
            });
            let router = router.clone();
            let pool = pool.clone();
            let metrics = metrics.clone();
            let completed = completed_tx.clone();
            let period = Duration::from_secs(config.collection_interval_secs);
            let gap = Duration::from_secs(config.gap_reset_threshold_secs);
            tasks.spawn(async move {
                run_schedule(period, || async {
                    router_task::collect_router(&router, &pool, &metrics, gap).await;
                    let _ = completed.send(router.name.clone()).await;
                })
                .await;
            });
        }
        drop(completed_tx);
        tasks.spawn(cleanup::run_pool_cleanup(pool.clone()));

        let active_routers: HashSet<_> = config
            .routers
            .iter()
            .map(|router| router.name.clone())
            .collect();
        let mut pending = active_routers.clone();
        let mut cycle_start = Instant::now();
        let mut cleanup_tick =
            tokio::time::interval(Duration::from_secs(config.collection_interval_secs * 20));
        cleanup_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let result = loop {
            tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break Ok(());
                    }
                }
                result = tasks.join_next() => {
                    break Err(AppError::Io(IoError::other(format!("Collector worker stopped unexpectedly: {result:?}"))));
                }
                Some(router) = completed_rx.recv() => {
                    pending.remove(&router);
                    if pending.is_empty() {
                        metrics.record_collection_cycle_duration(cycle_start.elapsed().as_secs_f64());
                        pending.clone_from(&active_routers);
                        cycle_start = Instant::now();
                    }
                    let (total, active) = pool.get_pool_stats().await;
                    metrics.update_pool_stats(total, active);
                }
                _ = cleanup_tick.tick() => {
                    metrics.cleanup_expired_dynamic_labels(STALE_LABEL_TTL);
                    metrics.cleanup_stale_routers(&active_routers);
                    pool.cleanup_states(&config.routers).await;
                }
            }
        };
        tasks.shutdown().await;
        result
    })
}

async fn run_schedule<F, Fut>(period: Duration, mut collect: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        collect().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(start_paused = true)]
    async fn test_slow_router_does_not_block_other_schedules() {
        let fast_count = Arc::new(AtomicUsize::new(0));
        let count = fast_count.clone();
        let mut tasks = JoinSet::new();
        tasks.spawn(run_schedule(Duration::from_secs(1), move || {
            count.fetch_add(1, Ordering::SeqCst);
            async {}
        }));
        tasks.spawn(run_schedule(Duration::from_secs(1), || async {
            std::future::pending::<()>().await;
        }));
        tokio::task::yield_now().await;
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(fast_count.load(Ordering::SeqCst), 4);
        tasks.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_collector_exits_on_closed_or_already_signalled_channel() {
        for signalled in [false, true] {
            let (tx, rx) = watch::channel(signalled);
            if !signalled {
                drop(tx);
            }
            let handle = start_collection_loop(
                rx,
                Arc::new(Config::default()),
                MetricsRegistry::new(),
                Arc::new(ConnectionPool::new()),
            );
            tokio::time::timeout(Duration::from_secs(1), handle)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn test_collector_invalid_programmatic_configuration_returns_error() {
        let (_tx, rx) = watch::channel(false);
        let config = Config {
            collection_interval_secs: 0,
            ..Config::default()
        };
        assert!(
            start_collection_loop(
                rx,
                Arc::new(config),
                MetricsRegistry::new(),
                Arc::new(ConnectionPool::new())
            )
            .await
            .unwrap()
            .is_err()
        );
    }
}
