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

        // Deterministic family-fair selection: `ip_version` lexically sorts
        // `"ipv4"` before `"ipv6"`, so a plain sorted `take(cap)` lets a large
        // IPv4 family exhaust the budget and evict the entire IPv6 family.
        // Round-robin across families keeps the total cap while giving each
        // family a fair share, so IPv6 survives an IPv4-saturated table.
        let mut families: BTreeMap<String, Vec<(String, String, u64)>> = BTreeMap::new();
        for ((ip_version, src_address, protocol), count) in candidates {
            families
                .entry(ip_version)
                .or_default()
                .push((src_address, protocol, count));
        }
        let mut offsets = vec![0; families.len()];
        let mut current_conntrack = HashSet::new();
        let now = Instant::now();
        let mut chosen = 0;
        loop {
            let mut advanced = false;
            for (index, (ip_version, series)) in families.iter().enumerate() {
                if chosen == SERIES_LIMIT_PER_ROUTER {
                    break;
                }
                let offset = &mut offsets[index];
                if *offset < series.len() {
                    let (src_address, protocol, count) = series[*offset].clone();
                    *offset += 1;
                    chosen += 1;
                    advanced = true;
                    let ct_labels = ConntrackLabels {
                        router: router_name.into(),
                        src_address,
                        protocol,
                        ip_version: ip_version.clone(),
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
            }
            if !advanced {
                break;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::registry::MetricsRegistry;
    use crate::metrics::registry::test_support::*;
    use crate::mikrotik::{CollectionStatus, CollectionStatusParts, FetchState};

    #[tokio::test]
    async fn test_conntrack_limit_is_deterministic_under_churn_and_partial_updates() {
        let registry = MetricsRegistry::new();
        let mut snapshot =
            make_router_metrics("router1", Vec::new(), make_system("7.10", "board", "1d"));
        snapshot.connection_tracking = (0..1100)
            .map(|i| make_conntrack(&format!("10.0.{}.{}", i / 256, i % 256), "tcp", 1, "ipv4"))
            .collect();
        registry.update_metrics(&snapshot);
        let first = registry.conntrack.prev.get("router1").unwrap().clone();
        assert_eq!(first.len(), SERIES_LIMIT_PER_ROUTER);
        snapshot.connection_tracking.reverse();
        registry.update_metrics(&snapshot);
        assert_eq!(*registry.conntrack.prev.get("router1").unwrap(), first);
        let labels = RouterLabels {
            router: "router1".into(),
        };
        assert_eq!(
            registry
                .conntrack
                .dropped_series
                .get_or_create(&labels)
                .get(),
            76
        );
        for prefix in ["192.0", "172.16", "10.1"] {
            snapshot.connection_tracking = (0..1100)
                .map(|i| {
                    make_conntrack(
                        &format!("{prefix}.{}.{}", i / 256, i % 256),
                        "tcp",
                        1,
                        "ipv4",
                    )
                })
                .collect();
            registry.update_metrics(&snapshot);
            assert_eq!(registry.conntrack.last_seen.len(), SERIES_LIMIT_PER_ROUTER);
            let encoded = registry.encode_metrics().await.unwrap();
            assert_eq!(
                encoded
                    .lines()
                    .filter(|line| line.starts_with("mikrotik_connection_tracking_count{"))
                    .count(),
                SERIES_LIMIT_PER_ROUTER
            );
            snapshot.collection_status = CollectionStatus::from_parts(CollectionStatusParts {
                conntrack: FetchState::Partial,
                ..Default::default()
            });
        }
        registry.cleanup_stale_routers(&std::collections::HashSet::new());
        assert!(!registry.encode_metrics().await.unwrap().contains("router1"));
    }

    #[test]
    fn test_partial_conntrack_does_not_refresh_missing_series_ttl() {
        let registry = MetricsRegistry::new();
        let mut snapshot =
            make_router_metrics("router1", Vec::new(), make_system("7.10", "board", "1d"));
        snapshot.connection_tracking = vec![make_conntrack("192.0.2.1", "tcp", 1, "ipv4")];
        registry.update_metrics(&snapshot);
        let labels = crate::metrics::labels::ConntrackLabels {
            router: "router1".into(),
            src_address: "192.0.2.1".into(),
            protocol: "tcp".into(),
            ip_version: "ipv4".into(),
        };
        registry.conntrack.last_seen.insert(
            labels.clone(),
            Instant::now() - std::time::Duration::from_secs(100),
        );
        snapshot.collection_status = CollectionStatus::from_parts(CollectionStatusParts {
            conntrack: FetchState::Partial,
            ..Default::default()
        });
        snapshot.connection_tracking.clear();
        registry.update_metrics(&snapshot);
        registry.cleanup_expired_dynamic_labels(std::time::Duration::from_secs(60));
        assert!(!registry.conntrack.last_seen.contains_key(&labels));
        assert!(registry.conntrack.prev.get("router1").unwrap().is_empty());
        assert_eq!(
            registry
                .conntrack
                .active_series
                .get_or_create(&RouterLabels {
                    router: "router1".into()
                })
                .get(),
            0
        );
    }

    #[tokio::test]
    async fn test_conntrack_cap_is_family_fair_when_ipv4_saturates() {
        let registry = MetricsRegistry::new();
        let mut snapshot =
            make_router_metrics("router1", Vec::new(), make_system("7.10", "board", "1d"));
        let mut tracking: Vec<_> = (0..1600)
            .map(|i| make_conntrack(&format!("10.0.{}.{}", i / 256, i % 256), "tcp", 1, "ipv4"))
            .collect();
        tracking.push(make_conntrack("2001:db8::1", "tcp", 1, "ipv6"));
        tracking.push(make_conntrack("2001:db8::2", "udp", 1, "ipv6"));
        tracking.push(make_conntrack("fe80::1", "tcp", 1, "ipv6"));
        snapshot.connection_tracking = tracking;
        registry.update_metrics(&snapshot);

        let prev = registry.conntrack.prev.get("router1").unwrap();
        assert_eq!(prev.len(), SERIES_LIMIT_PER_ROUTER);
        for expected in [
            ("2001:db8::1", "tcp"),
            ("2001:db8::2", "udp"),
            ("fe80::1", "tcp"),
        ] {
            let labels = crate::metrics::labels::ConntrackLabels {
                router: "router1".into(),
                src_address: expected.0.into(),
                protocol: expected.1.into(),
                ip_version: "ipv6".into(),
            };
            assert!(
                prev.contains(&labels),
                "IPv6 series {} must survive an IPv4-saturated cap",
                expected.0
            );
            assert!(registry.conntrack.count.get_or_create(&labels).get() >= 1);
        }
        let router_labels = RouterLabels {
            router: "router1".into(),
        };
        assert_eq!(
            registry
                .conntrack
                .dropped_series
                .get_or_create(&router_labels)
                .get(),
            i64::try_from(1603 - SERIES_LIMIT_PER_ROUTER).unwrap()
        );
    }

    #[tokio::test]
    async fn test_conntrack_cap_single_family_preserves_determinism() {
        let registry = MetricsRegistry::new();
        let mut snapshot =
            make_router_metrics("router2", Vec::new(), make_system("7.10", "board", "1d"));
        snapshot.connection_tracking = (0..1200)
            .map(|i| {
                make_conntrack(
                    &format!("192.0.2.{}.{}", i / 256, i % 256),
                    "udp",
                    1,
                    "ipv4",
                )
            })
            .collect();
        registry.update_metrics(&snapshot);
        let first = registry.conntrack.prev.get("router2").unwrap().clone();
        assert_eq!(first.len(), SERIES_LIMIT_PER_ROUTER);
        snapshot.connection_tracking.reverse();
        registry.update_metrics(&snapshot);
        assert_eq!(*registry.conntrack.prev.get("router2").unwrap(), first);
    }

    #[tokio::test]
    async fn test_connection_tracking_multi_outter() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("*1", "ether1", "", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d2h3m4s");

        let mut metrics1 = make_router_metrics("router1", vec![iface.clone()], system.clone());
        metrics1.connection_tracking = vec![
            make_conntrack("192.168.1.1", "tcp", 100, "ipv4"),
            make_conntrack("192.168.1.1", "udp", 50, "ipv4"),
        ];
        registry.update_metrics(&metrics1);

        let mut metrics2 = make_router_metrics("router2", vec![iface.clone()], system.clone());
        metrics2.connection_tracking = vec![
            make_conntrack("10.0.0.1", "tcp", 200, "ipv4"),
            make_conntrack("10.0.0.1", "icmp", 10, "ipv4"),
        ];
        registry.update_metrics(&metrics2);

        let labels1_tcp = crate::metrics::labels::ConntrackLabels {
            router: "router1".to_string(),
            src_address: "192.168.1.1".to_string(),
            protocol: "tcp".to_string(),
            ip_version: "ipv4".to_string(),
        };
        let labels1_udp = crate::metrics::labels::ConntrackLabels {
            router: "router1".to_string(),
            src_address: "192.168.1.1".to_string(),
            protocol: "udp".to_string(),
            ip_version: "ipv4".to_string(),
        };
        let labels2_tcp = crate::metrics::labels::ConntrackLabels {
            router: "router2".to_string(),
            src_address: "10.0.0.1".to_string(),
            protocol: "tcp".to_string(),
            ip_version: "ipv4".to_string(),
        };
        let labels2_icmp = crate::metrics::labels::ConntrackLabels {
            router: "router2".to_string(),
            src_address: "10.0.0.1".to_string(),
            protocol: "icmp".to_string(),
            ip_version: "ipv4".to_string(),
        };

        assert_eq!(
            registry.conntrack.count.get_or_create(&labels1_tcp).get(),
            100
        );
        assert_eq!(
            registry.conntrack.count.get_or_create(&labels1_udp).get(),
            50
        );
        assert_eq!(
            registry.conntrack.count.get_or_create(&labels2_tcp).get(),
            200
        );
        assert_eq!(
            registry.conntrack.count.get_or_create(&labels2_icmp).get(),
            10
        );

        metrics1.connection_tracking = vec![make_conntrack("192.168.1.1", "tcp", 150, "ipv4")];
        registry.update_metrics(&metrics1);

        assert_eq!(
            registry.conntrack.count.get_or_create(&labels1_tcp).get(),
            150
        );
        assert_eq!(
            registry.conntrack.count.get_or_create(&labels1_udp).get(),
            0
        );

        assert_eq!(
            registry.conntrack.count.get_or_create(&labels2_tcp).get(),
            200
        );
        assert_eq!(
            registry.conntrack.count.get_or_create(&labels2_icmp).get(),
            10
        );
    }

    #[tokio::test]
    async fn test_conntrack_observability_metrics_updated() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("*1", "ether1", "", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d");

        let mut metrics = make_router_metrics("router1", vec![iface], system);
        metrics.connection_tracking = vec![
            make_conntrack("192.168.1.1", "tcp", 100, "ipv4"),
            make_conntrack("192.168.1.1", "udp", 50, "ipv4"),
        ];
        registry.update_metrics(&metrics);

        let router_labels = RouterLabels {
            router: "router1".to_string(),
        };

        assert_eq!(
            registry
                .conntrack
                .active_series
                .get_or_create(&router_labels)
                .get(),
            2
        );
        assert!(
            registry
                .conntrack
                .update_duration_seconds
                .get_or_create(&router_labels)
                .get()
                >= 0.0
        );
    }

    #[tokio::test]
    async fn test_conntrack_observability_for_ten_routers() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("*1", "ether1", "", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d");

        for router_index in 0..10 {
            let router_name = format!("router-{router_index}");
            let mut metrics =
                make_router_metrics(&router_name, vec![iface.clone()], system.clone());
            metrics.connection_tracking = vec![
                make_conntrack("192.168.1.1", "tcp", 100, "ipv4"),
                make_conntrack("192.168.1.1", "udp", 50, "ipv4"),
                make_conntrack("2001:db8::1", "tcp", 20, "ipv6"),
            ];
            registry.update_metrics(&metrics);

            let router_labels = RouterLabels {
                router: router_name,
            };
            assert_eq!(
                registry
                    .conntrack
                    .active_series
                    .get_or_create(&router_labels)
                    .get(),
                3
            );
            assert!(
                registry
                    .conntrack
                    .update_duration_seconds
                    .get_or_create(&router_labels)
                    .get()
                    >= 0.0
            );
        }
    }

    #[tokio::test]
    async fn test_conntrack_partial_snapshot_preserves_previous_series() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("*1", "ether1", "", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d");

        let mut metrics_full = make_router_metrics("router1", vec![iface.clone()], system.clone());
        metrics_full.connection_tracking = vec![
            make_conntrack("192.168.1.1", "tcp", 100, "ipv4"),
            make_conntrack("192.168.1.1", "udp", 50, "ipv4"),
        ];
        registry.update_metrics(&metrics_full);

        let mut metrics_partial =
            make_router_metrics("router1", vec![iface.clone()], system.clone());
        metrics_partial.collection_status = make_partial_status(
            FetchState::Partial,
            FetchState::Failed,
            FetchState::Failed,
            FetchState::Failed,
        );
        metrics_partial.connection_tracking =
            vec![make_conntrack("192.168.1.1", "tcp", 150, "ipv4")];
        registry.update_metrics(&metrics_partial);

        let labels_tcp = crate::metrics::labels::ConntrackLabels {
            router: "router1".to_string(),
            src_address: "192.168.1.1".to_string(),
            protocol: "tcp".to_string(),
            ip_version: "ipv4".to_string(),
        };
        let labels_udp = crate::metrics::labels::ConntrackLabels {
            router: "router1".to_string(),
            src_address: "192.168.1.1".to_string(),
            protocol: "udp".to_string(),
            ip_version: "ipv4".to_string(),
        };

        assert_eq!(
            registry.conntrack.count.get_or_create(&labels_tcp).get(),
            150
        );
        assert_eq!(
            registry.conntrack.count.get_or_create(&labels_udp).get(),
            50,
            "UDP series should be preserved during partial conntrack snapshot"
        );
    }
}
