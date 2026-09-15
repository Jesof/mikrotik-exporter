// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Scrape and registry-level bookkeeping helpers

use crate::metrics::labels::{GroupLabels, RouterLabels};
use crate::mikrotik::CollectionStatus;
use crate::prelude::{AppError, Result};
use prometheus_client::encoding::text::encode;
use std::time::Duration;
use tokio::time::Instant;

use super::MetricsRegistry;

impl MetricsRegistry {
    /// Encode all metrics to `OpenMetrics` text format.
    ///
    /// # Errors
    /// Returns an error if Prometheus encoding fails.
    pub async fn encode_metrics(&self) -> Result<String> {
        let registry = self.registry.lock().await;
        let mut buffer = String::new();
        encode(&mut buffer, &registry)
            .map_err(|error| AppError::Metrics(format!("OpenMetrics encode error: {error}")))?;
        Ok(buffer)
    }

    pub fn record_scrape_success(&self, labels: &RouterLabels) {
        self.scrape_success.get_or_create(labels).inc();
        // Record timestamp of successful scrape
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        #[allow(clippy::cast_possible_wrap)]
        self.scrape_last_success_timestamp_seconds
            .get_or_create(labels)
            .set(now as i64);
        self.last_scrape_success
            .insert(labels.router.clone(), Instant::now());
        self.consecutive_scrape_errors
            .insert(labels.router.clone(), 0);
    }

    /// Record scrape success and return gap duration if it exceeds threshold.
    #[must_use]
    pub fn record_scrape_success_and_check_gap(
        &self,
        labels: &RouterLabels,
        now: Instant,
        reset_threshold: Duration,
    ) -> Option<Duration> {
        self.scrape_success.get_or_create(labels).inc();
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        #[allow(clippy::cast_possible_wrap)]
        self.scrape_last_success_timestamp_seconds
            .get_or_create(labels)
            .set(now_epoch as i64);

        let previous = self
            .last_scrape_success
            .get(&labels.router)
            .map(|r| *r.value());
        let had_errors = self
            .consecutive_scrape_errors
            .get(&labels.router)
            .is_some_and(|errors| *errors.value() > 0);

        self.last_scrape_success.insert(labels.router.clone(), now);
        self.consecutive_scrape_errors
            .insert(labels.router.clone(), 0);

        match previous {
            Some(previous_time) => {
                let gap = now.duration_since(previous_time);
                if gap > reset_threshold || had_errors {
                    Some(gap)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    pub fn record_scrape_error(&self, labels: &RouterLabels) {
        self.record_group_status(labels, &CollectionStatus::from_group_results([false; 4]));
        self.scrape_errors.get_or_create(labels).inc();
        self.consecutive_scrape_errors
            .entry(labels.router.clone())
            .and_modify(|errors| *errors = errors.saturating_add(1))
            .or_insert(1);
    }

    /// Initialize metrics for a router to zero
    ///
    /// This ensures that counters like `scrape_success` and `scrape_errors`
    /// exist from the start, allowing Prometheus to calculate rates correctly
    /// even before the first success or error occurs. It also pre-creates the
    /// per-router `conntrack` gauges so their families are rendered (with zero
    /// values) before the first conntrack update.
    pub fn initialize_router_metrics(&self, labels: &RouterLabels) {
        self.known_routers.insert(labels.router.clone(), ());
        let _ = self.scrape_success.get_or_create(labels);
        let _ = self.scrape_errors.get_or_create(labels);
        let _ = self.scrape_duration_seconds.get_or_create(labels);
        let _ = self
            .scrape_last_success_timestamp_seconds
            .get_or_create(labels);
        let _ = self.conntrack_dropped_series.get_or_create(labels);
        for (group, _) in CollectionStatus::default().group_states() {
            let group_labels = GroupLabels {
                router: labels.router.clone(),
                group,
            };
            let _ = self.group_collection_success.get_or_create(&group_labels);
            let _ = self.group_collection_complete.get_or_create(&group_labels);
            let _ = self
                .group_last_success_timestamp_seconds
                .get_or_create(&group_labels);
        }
        let _ = self.connection_consecutive_errors.get_or_create(labels);
        let _ = self.conntrack_active_series.get_or_create(labels);
        let _ = self.conntrack_update_duration_seconds.get_or_create(labels);
    }

    pub fn record_scrape_duration(&self, labels: &RouterLabels, duration_secs: f64) {
        self.scrape_duration_seconds
            .get_or_create(labels)
            .set(duration_secs);
    }

    pub fn record_collection_cycle_duration(&self, duration_secs: f64) {
        self.collection_cycle_duration_seconds.set(duration_secs);
    }

    pub fn record_group_status(&self, labels: &RouterLabels, status: &CollectionStatus) {
        self.initialize_router_metrics(labels);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
            });
        for (group, state) in status.group_states() {
            let labels = GroupLabels {
                router: labels.router.clone(),
                group,
            };
            self.group_collection_success
                .get_or_create(&labels)
                .set(i64::from(state.any_ok()));
            self.group_collection_complete
                .get_or_create(&labels)
                .set(i64::from(state.complete()));
            if state.complete() {
                self.group_last_success_timestamp_seconds
                    .get_or_create(&labels)
                    .set(timestamp);
            }
        }
    }

    pub fn update_connection_errors(&self, labels: &RouterLabels, consecutive_errors: u32) {
        self.connection_consecutive_errors
            .get_or_create(labels)
            .set(i64::from(consecutive_errors));
    }

    pub fn update_pool_stats(&self, total: usize, active: usize) {
        #[allow(clippy::cast_possible_wrap)]
        {
            self.connection_pool_size.set(total as i64);
            self.connection_pool_active.set(active as i64);
        }
    }

    /// Get scrape success count for health check
    #[must_use]
    pub fn get_scrape_success_count(&self, labels: &RouterLabels) -> u64 {
        self.scrape_success.get_or_create(labels).get()
    }

    /// Get scrape error count for health check
    #[must_use]
    pub fn get_scrape_error_count(&self, labels: &RouterLabels) -> u64 {
        self.scrape_errors.get_or_create(labels).get()
    }

    #[must_use]
    pub fn get_last_scrape_success_age(&self, router: &str) -> Option<Duration> {
        self.last_scrape_success
            .get(router)
            .map(|instant| instant.elapsed())
    }
}
