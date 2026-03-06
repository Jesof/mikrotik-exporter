// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Scrape and registry-level bookkeeping helpers

use crate::metrics::labels::RouterLabels;
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
    /// even before the first success or error occurs.
    pub fn initialize_router_metrics(&self, labels: &RouterLabels) {
        let _ = self.scrape_success.get_or_create(labels);
        let _ = self.scrape_errors.get_or_create(labels);
        let _ = self.scrape_duration_milliseconds.get_or_create(labels);
        let _ = self.connection_consecutive_errors.get_or_create(labels);
    }

    pub fn record_scrape_duration(&self, labels: &RouterLabels, duration_secs: f64) {
        // Store as milliseconds for better precision (will be interpreted as fractional seconds)
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let millis = (duration_secs * 1000.0).round() as i64;
        self.scrape_duration_milliseconds
            .get_or_create(labels)
            .set(millis);
    }

    pub fn record_collection_cycle_duration(&self, duration_secs: f64) {
        // Store as milliseconds for better precision (will be interpreted as fractional seconds)
        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
        let millis = (duration_secs * 1000.0).round() as i64;
        self.collection_cycle_duration_milliseconds.set(millis);
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
