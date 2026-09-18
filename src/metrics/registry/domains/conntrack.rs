// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Connection tracking metrics domain.

use crate::metrics::labels::{ConntrackLabels, RouterLabels};
use crate::mikrotik::ConnectionTrackingStats;
use dashmap::DashMap;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use tokio::time::Instant;

type FloatGauge = Gauge<f64, std::sync::atomic::AtomicU64>;
pub(crate) const SERIES_LIMIT_PER_ROUTER: usize = 1024;

#[derive(Clone)]
pub(crate) struct ConntrackDomain {
    pub(crate) count: Family<ConntrackLabels, Gauge>,
    pub(crate) active_series: Family<RouterLabels, Gauge>,
    pub(crate) update_duration_seconds: Family<RouterLabels, FloatGauge>,
    pub(crate) dropped_series: Family<RouterLabels, Gauge>,
    pub(crate) prev: Arc<DashMap<String, HashSet<ConntrackLabels>>>,
    pub(crate) last_seen: Arc<DashMap<ConntrackLabels, Instant>>,
}

impl ConntrackDomain {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let count = Family::<ConntrackLabels, Gauge>::default();
        registry.register(
            "mikrotik_connection_tracking_count",
            "Number of tracked connections per source address and protocol",
            count.clone(),
        );
        let active_series = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_conntrack_active_series",
            "Number of active conntrack label series per router",
            active_series.clone(),
        );
        let update_duration_seconds = Family::<RouterLabels, FloatGauge>::default();
        registry.register(
            "mikrotik_conntrack_update_duration_seconds",
            "Duration of conntrack metrics update in seconds",
            update_duration_seconds.clone(),
        );
        let dropped_series = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_conntrack_dropped_series",
            "Conntrack series omitted from latest snapshot by the 1024 series per router limit",
            dropped_series.clone(),
        );

        Self {
            count,
            active_series,
            update_duration_seconds,
            dropped_series,
            prev: Arc::new(DashMap::new()),
            last_seen: Arc::new(DashMap::new()),
        }
    }

    pub(crate) fn update(
        &self,
        router_name: &str,
        connection_tracking: &[ConnectionTrackingStats],
        conntrack_ok: bool,
        conntrack_complete_ok: bool,
    ) {
        let started_at = Instant::now();
        let router_labels = RouterLabels {
            router: router_name.into(),
        };

        if !conntrack_ok {
            tracing::debug!(router = %router_name, "Skipping conntrack metric update due to partial collection");
            self.update_duration_seconds
                .get_or_create(&router_labels)
                .set(0.0);
            return;
        }

        let mut candidates = BTreeMap::new();
        for ct in connection_tracking {
            let key = (
                ct.ip_version.clone(),
                ct.src_address.clone(),
                ct.protocol.clone(),
            );
            let count = candidates.entry(key).or_insert(0u64);
            *count = count.saturating_add(ct.connection_count);
        }
        let observed: HashSet<_> = candidates.keys().cloned().collect();
        let snapshot_series = candidates.len();

        let mut prev_map_entry = self.prev.entry(router_name.into()).or_default();
        let prev_labels = prev_map_entry.value_mut();
        if !conntrack_complete_ok {
            for labels in prev_labels.iter() {
                candidates
                    .entry((
                        labels.ip_version.clone(),
                        labels.src_address.clone(),
                        labels.protocol.clone(),
                    ))
                    .or_insert_with(|| {
                        u64::try_from(self.count.get_or_create(labels).get()).unwrap_or(0)
                    });
            }
        }

        let mut current_conntrack = HashSet::new();
        let now = Instant::now();
        for ((ip_version, src_address, protocol), count) in
            candidates.into_iter().take(SERIES_LIMIT_PER_ROUTER)
        {
            let ct_labels = ConntrackLabels {
                router: router_name.into(),
                src_address,
                protocol,
                ip_version,
            };
            current_conntrack.insert(ct_labels.clone());
            #[allow(clippy::cast_possible_wrap)]
            self.count
                .get_or_create(&ct_labels)
                .set(i64::try_from(count).unwrap_or(i64::MAX));
            if observed.contains(&(
                ct_labels.ip_version.clone(),
                ct_labels.src_address.clone(),
                ct_labels.protocol.clone(),
            )) {
                self.last_seen.insert(ct_labels, now);
            }
        }

        let active_series_count = current_conntrack.len();
        let retained_observed = current_conntrack
            .iter()
            .filter(|labels| {
                observed.contains(&(
                    labels.ip_version.clone(),
                    labels.src_address.clone(),
                    labels.protocol.clone(),
                ))
            })
            .count();
        for stale in prev_labels.difference(&current_conntrack) {
            self.count.remove(stale);
            self.last_seen.remove(stale);
        }
        *prev_labels = current_conntrack;
        self.dropped_series.get_or_create(&router_labels).set(
            i64::try_from(snapshot_series.saturating_sub(retained_observed)).unwrap_or(i64::MAX),
        );

        #[allow(clippy::cast_possible_wrap)]
        self.active_series
            .get_or_create(&router_labels)
            .set(active_series_count as i64);

        #[allow(clippy::cast_precision_loss)]
        self.update_duration_seconds
            .get_or_create(&router_labels)
            .set(started_at.elapsed().as_secs_f64());
    }

    pub(crate) fn cleanup_expired(&self, now: Instant, ttl: std::time::Duration) {
        let stale: Vec<ConntrackLabels> = self
            .last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();

        for label in &stale {
            self.last_seen.remove(label);
        }
        if !stale.is_empty() {
            let count = stale.len();
            for label in &stale {
                if let Some(mut set) = self.prev.get_mut(&label.router) {
                    set.remove(label);
                }
                self.count.remove(label);
            }
            tracing::debug!(expired = count, "Expired conntrack labels via TTL cleanup");
            for entry in self.prev.iter() {
                self.active_series
                    .get_or_create(&RouterLabels {
                        router: entry.key().clone(),
                    })
                    .set(i64::try_from(entry.value().len()).unwrap_or(i64::MAX));
            }
        }
    }

    pub(crate) fn cleanup_stale_router(&self, router_name: &str) {
        if let Some((_, set)) = self.prev.remove(router_name) {
            for label in &set {
                self.count.remove(label);
                self.last_seen.remove(label);
            }
        }
    }
}
