// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Scrape and registry-level bookkeeping helpers

use crate::metrics::labels::RouterLabels;
use prometheus_client::encoding::text::encode;

use super::MetricsRegistry;

impl MetricsRegistry {
    pub async fn encode_metrics(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let registry = self.registry.lock().await;
        let mut buffer = String::new();
        encode(&mut buffer, &registry)?;
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
    }

    pub fn record_scrape_error(&self, labels: &RouterLabels) {
        self.scrape_errors.get_or_create(labels).inc();
    }

    /// Initialize metrics for a router to zero
    ///
    /// This ensures that counters like scrape_success and scrape_errors
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
    pub async fn get_scrape_success_count(&self, labels: &RouterLabels) -> u64 {
        self.scrape_success.get_or_create(labels).get()
    }

    /// Get scrape error count for health check
    pub async fn get_scrape_error_count(&self, labels: &RouterLabels) -> u64 {
        self.scrape_errors.get_or_create(labels).get()
    }
}
