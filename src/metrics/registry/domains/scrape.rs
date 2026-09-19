// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Scrape and collection bookkeeping domain.

use crate::metrics::labels::{GroupLabels, RouterLabels};
use crate::mikrotik::CollectionStatus;
use dashmap::DashMap;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

type FloatGauge = Gauge<f64, std::sync::atomic::AtomicU64>;

#[derive(Clone)]
pub(crate) struct ScrapeDomain {
    pub(crate) success: Family<RouterLabels, Counter>,
    pub(crate) errors: Family<RouterLabels, Counter>,
    pub(crate) duration_seconds: Family<RouterLabels, FloatGauge>,
    pub(crate) last_success_timestamp_seconds: Family<RouterLabels, Gauge>,
    pub(crate) connection_consecutive_errors: Family<RouterLabels, Gauge>,
    pub(crate) collection_cycle_duration_seconds: FloatGauge,
    pub(crate) group_collection_success: Family<GroupLabels, Gauge>,
    pub(crate) group_collection_complete: Family<GroupLabels, Gauge>,
    pub(crate) group_last_success_timestamp_seconds: Family<GroupLabels, Gauge>,
    pub(crate) last_scrape_success: Arc<DashMap<String, Instant>>,
    pub(crate) consecutive_scrape_errors: Arc<DashMap<String, u32>>,
}

impl ScrapeDomain {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let success = Family::<RouterLabels, Counter>::default();
        registry.register(
            "mikrotik_scrape_success",
            "Successful scrape cycles per router",
            success.clone(),
        );
        let errors = Family::<RouterLabels, Counter>::default();
        registry.register(
            "mikrotik_scrape_errors",
            "Failed scrape cycles per router",
            errors.clone(),
        );
        let duration_seconds = Family::<RouterLabels, FloatGauge>::default();
        registry.register(
            "mikrotik_scrape_duration_seconds",
            "Duration of last scrape in seconds",
            duration_seconds.clone(),
        );
        let last_success_timestamp_seconds = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_scrape_last_success_timestamp_seconds",
            "Unix timestamp of last successful scrape",
            last_success_timestamp_seconds.clone(),
        );
        let connection_consecutive_errors = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_connection_consecutive_errors",
            "Number of consecutive connection errors",
            connection_consecutive_errors.clone(),
        );
        let collection_cycle_duration_seconds = FloatGauge::default();
        registry.register(
            "mikrotik_collection_cycle_duration_seconds",
            "Duration of full collection cycle in seconds",
            collection_cycle_duration_seconds.clone(),
        );
        let group_collection_success = Family::<GroupLabels, Gauge>::default();
        registry.register(
            "mikrotik_group_collection_success",
            "Last collection returned usable group data (1=yes, 0=no)",
            group_collection_success.clone(),
        );
        let group_collection_complete = Family::<GroupLabels, Gauge>::default();
        registry.register(
            "mikrotik_group_collection_complete",
            "Last collection returned a complete group snapshot (1=yes, 0=no)",
            group_collection_complete.clone(),
        );
        let group_last_success_timestamp_seconds = Family::<GroupLabels, Gauge>::default();
        registry.register(
            "mikrotik_group_last_success_timestamp_seconds",
            "Unix timestamp of last complete group collection (0=never)",
            group_last_success_timestamp_seconds.clone(),
        );

        Self {
            success,
            errors,
            duration_seconds,
            last_success_timestamp_seconds,
            connection_consecutive_errors,
            collection_cycle_duration_seconds,
            group_collection_success,
            group_collection_complete,
            group_last_success_timestamp_seconds,
            last_scrape_success: Arc::new(DashMap::new()),
            consecutive_scrape_errors: Arc::new(DashMap::new()),
        }
    }

    pub(crate) fn record_success(&self, labels: &RouterLabels) {
        self.success.get_or_create(labels).inc();
        self.last_success_timestamp_seconds
            .get_or_create(labels)
            .set(now_epoch_i64());
        self.last_scrape_success
            .insert(labels.router.clone(), Instant::now());
        self.consecutive_scrape_errors
            .insert(labels.router.clone(), 0);
    }

    #[must_use]
    pub(crate) fn record_success_and_check_gap(
        &self,
        labels: &RouterLabels,
        now: Instant,
        reset_threshold: Duration,
    ) -> Option<Duration> {
        self.success.get_or_create(labels).inc();
        self.last_success_timestamp_seconds
            .get_or_create(labels)
            .set(now_epoch_i64());

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

    pub(crate) fn record_error(&self, labels: &RouterLabels) {
        self.record_group_status(labels, &CollectionStatus::from_group_results([false; 4]));
        self.errors.get_or_create(labels).inc();
        self.consecutive_scrape_errors
            .entry(labels.router.clone())
            .and_modify(|errors| *errors = errors.saturating_add(1))
            .or_insert(1);
    }

    pub(crate) fn record_duration(&self, labels: &RouterLabels, duration_secs: f64) {
        self.duration_seconds
            .get_or_create(labels)
            .set(duration_secs);
    }

    pub(crate) fn record_collection_cycle_duration(&self, duration_secs: f64) {
        self.collection_cycle_duration_seconds.set(duration_secs);
    }

    pub(crate) fn record_group_status(&self, labels: &RouterLabels, status: &CollectionStatus) {
        self.initialize_router_metrics(labels);
        let timestamp = now_epoch_i64();
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

    pub(crate) fn update_connection_errors(&self, labels: &RouterLabels, consecutive_errors: u32) {
        self.connection_consecutive_errors
            .get_or_create(labels)
            .set(i64::from(consecutive_errors));
    }

    pub(crate) fn initialize_router_metrics(&self, labels: &RouterLabels) {
        let _ = self.success.get_or_create(labels);
        let _ = self.errors.get_or_create(labels);
        let _ = self.duration_seconds.get_or_create(labels);
        let _ = self.last_success_timestamp_seconds.get_or_create(labels);
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
    }

    #[must_use]
    pub(crate) fn get_success_count(&self, labels: &RouterLabels) -> u64 {
        self.success.get_or_create(labels).get()
    }

    #[must_use]
    pub(crate) fn get_error_count(&self, labels: &RouterLabels) -> u64 {
        self.errors.get_or_create(labels).get()
    }

    #[must_use]
    pub(crate) fn get_last_success_age(&self, router: &str) -> Option<Duration> {
        self.last_scrape_success
            .get(router)
            .map(|instant| instant.elapsed())
    }

    pub(crate) fn cleanup_stale_router(&self, router_name: &str) {
        let labels = RouterLabels {
            router: router_name.into(),
        };
        self.success.remove(&labels);
        self.errors.remove(&labels);
        self.duration_seconds.remove(&labels);
        self.last_success_timestamp_seconds.remove(&labels);
        self.connection_consecutive_errors.remove(&labels);
        for (group, _) in CollectionStatus::default().group_states() {
            let gl = GroupLabels {
                router: router_name.into(),
                group,
            };
            self.group_collection_success.remove(&gl);
            self.group_collection_complete.remove(&gl);
            self.group_last_success_timestamp_seconds.remove(&gl);
        }
        self.last_scrape_success.remove(router_name);
        self.consecutive_scrape_errors.remove(router_name);
    }
}

fn now_epoch_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use crate::metrics::labels::RouterLabels;
    use crate::metrics::registry::MetricsRegistry;
    use crate::metrics::registry::test_support::router_label;
    use crate::mikrotik::{CollectionStatus, CollectionStatusParts, FetchState};

    #[test]
    fn test_partial_group_status_does_not_advance_freshness() {
        let registry = MetricsRegistry::new();
        let labels = router_label("router1");
        registry.record_group_status(&labels, &CollectionStatus::default());
        let group = crate::metrics::labels::GroupLabels {
            router: labels.router.clone(),
            group: "conntrack",
        };
        registry
            .scrape
            .group_last_success_timestamp_seconds
            .get_or_create(&group)
            .set(123);
        let status = CollectionStatus::from_parts(CollectionStatusParts {
            conntrack: FetchState::Partial,
            ..Default::default()
        });
        registry.record_group_status(&labels, &status);
        assert_eq!(
            registry
                .scrape
                .group_collection_success
                .get_or_create(&group)
                .get(),
            1
        );
        assert_eq!(
            registry
                .scrape
                .group_collection_complete
                .get_or_create(&group)
                .get(),
            0
        );
        assert_eq!(
            registry
                .scrape
                .group_last_success_timestamp_seconds
                .get_or_create(&group)
                .get(),
            123
        );
        assert!(!status.all_ok());
        registry.record_scrape_error(&labels);
        assert_eq!(
            registry
                .scrape
                .group_collection_success
                .get_or_create(&group)
                .get(),
            0
        );
        assert_eq!(
            registry
                .scrape
                .group_last_success_timestamp_seconds
                .get_or_create(&group)
                .get(),
            123
        );
    }

    #[test]
    fn test_record_scrape_success_increments() {
        let registry = MetricsRegistry::new();
        let labels = router_label("router1");

        assert_eq!(registry.scrape.success.get_or_create(&labels).get(), 0);
        registry.record_scrape_success(&labels);
        assert_eq!(registry.scrape.success.get_or_create(&labels).get(), 1);
        registry.record_scrape_success(&labels);
        assert_eq!(registry.scrape.success.get_or_create(&labels).get(), 2);
    }

    #[test]
    fn test_record_scrape_error_increments() {
        let registry = MetricsRegistry::new();
        let labels = router_label("router1");

        assert_eq!(registry.scrape.errors.get_or_create(&labels).get(), 0);
        registry.record_scrape_error(&labels);
        assert_eq!(registry.scrape.errors.get_or_create(&labels).get(), 1);
        registry.record_scrape_error(&labels);
        assert_eq!(registry.scrape.errors.get_or_create(&labels).get(), 2);
    }

    #[test]
    fn test_record_collection_cycle_duration_sets_gauge() {
        let registry = MetricsRegistry::new();

        registry.record_collection_cycle_duration(0.012);
        assert!(
            (registry.scrape.collection_cycle_duration_seconds.get() - 0.012).abs() < f64::EPSILON
        );

        registry.record_collection_cycle_duration(1.234);
        assert!(
            (registry.scrape.collection_cycle_duration_seconds.get() - 1.234).abs() < f64::EPSILON
        );
    }

    #[test]
    fn test_update_connection_errors_sets_gauge() {
        let registry = MetricsRegistry::new();
        let labels = RouterLabels {
            router: "router1".to_string(),
        };

        registry.update_connection_errors(&labels, 0);
        assert_eq!(
            registry
                .scrape
                .connection_consecutive_errors
                .get_or_create(&labels)
                .get(),
            0
        );

        registry.update_connection_errors(&labels, 3);
        assert_eq!(
            registry
                .scrape
                .connection_consecutive_errors
                .get_or_create(&labels)
                .get(),
            3
        );
    }
}
