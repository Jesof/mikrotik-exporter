// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Scrape and registry-level bookkeeping: delegates to domain modules.

use crate::metrics::labels::RouterLabels;
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
        self.scrape.record_success(labels);
    }

    /// Record scrape success and return gap duration if it exceeds threshold.
    #[must_use]
    pub fn record_scrape_success_and_check_gap(
        &self,
        labels: &RouterLabels,
        now: Instant,
        reset_threshold: Duration,
    ) -> Option<Duration> {
        self.scrape
            .record_success_and_check_gap(labels, now, reset_threshold)
    }

    pub fn record_scrape_error(&self, labels: &RouterLabels) {
        self.scrape.record_error(labels);
    }

    pub fn record_scrape_duration(&self, labels: &RouterLabels, duration_secs: f64) {
        self.scrape.record_duration(labels, duration_secs);
    }

    pub fn record_collection_cycle_duration(&self, duration_secs: f64) {
        self.scrape.record_collection_cycle_duration(duration_secs);
    }

    pub fn record_group_status(&self, labels: &RouterLabels, status: &CollectionStatus) {
        self.scrape.record_group_status(labels, status);
    }

    pub fn update_connection_errors(&self, labels: &RouterLabels, consecutive_errors: u32) {
        self.scrape
            .update_connection_errors(labels, consecutive_errors);
    }

    pub fn update_pool_stats(&self, total: usize, active: usize) {
        self.pool.update(total, active);
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
        self.scrape.initialize_router_metrics(labels);
        let _ = self.conntrack.dropped_series.get_or_create(labels);
        let _ = self.conntrack.active_series.get_or_create(labels);
        let _ = self.conntrack.update_duration_seconds.get_or_create(labels);
    }

    /// Get scrape success count for health check
    #[must_use]
    pub fn get_scrape_success_count(&self, labels: &RouterLabels) -> u64 {
        self.scrape.get_success_count(labels)
    }

    /// Get scrape error count for health check
    #[must_use]
    pub fn get_scrape_error_count(&self, labels: &RouterLabels) -> u64 {
        self.scrape.get_error_count(labels)
    }

    #[must_use]
    pub fn get_last_scrape_success_age(&self, router: &str) -> Option<Duration> {
        self.scrape.get_last_success_age(router)
    }
}
