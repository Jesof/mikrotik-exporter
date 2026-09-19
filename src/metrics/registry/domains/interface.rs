// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Interface metrics domain.

use crate::metrics::labels::{InterfaceInfoLabels, InterfaceLabels};
use crate::mikrotik::InterfaceStats;
use dashmap::DashMap;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(crate) struct InterfaceSnapshot {
    pub(crate) rx_bytes: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_packets: u64,
    pub(crate) tx_packets: u64,
    pub(crate) rx_errors: Option<u64>,
    pub(crate) tx_errors: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct InterfaceDomain {
    pub(crate) rx_bytes: Family<InterfaceLabels, Counter>,
    pub(crate) tx_bytes: Family<InterfaceLabels, Counter>,
    pub(crate) rx_packets: Family<InterfaceLabels, Counter>,
    pub(crate) tx_packets: Family<InterfaceLabels, Counter>,
    pub(crate) rx_errors: Family<InterfaceLabels, Counter>,
    pub(crate) tx_errors: Family<InterfaceLabels, Counter>,
    pub(crate) running: Family<InterfaceLabels, Gauge>,
    pub(crate) info: Family<InterfaceInfoLabels, Gauge>,
    pub(crate) prev: Arc<DashMap<InterfaceLabels, InterfaceSnapshot>>,
    pub(crate) prev_info: Arc<DashMap<String, HashMap<InterfaceLabels, InterfaceInfoLabels>>>,
    pub(crate) info_last_seen: Arc<DashMap<InterfaceInfoLabels, Instant>>,
    seeded_routers: Arc<DashMap<String, ()>>,
}

impl InterfaceDomain {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let rx_bytes = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_rx_bytes",
            "Received bytes on interface",
            rx_bytes.clone(),
        );
        let tx_bytes = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_tx_bytes",
            "Transmitted bytes on interface",
            tx_bytes.clone(),
        );
        let rx_packets = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_rx_packets",
            "Received packets on interface",
            rx_packets.clone(),
        );
        let tx_packets = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_tx_packets",
            "Transmitted packets on interface",
            tx_packets.clone(),
        );
        let rx_errors = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_rx_errors",
            "Receive errors on interface",
            rx_errors.clone(),
        );
        let tx_errors = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_tx_errors",
            "Transmit errors on interface",
            tx_errors.clone(),
        );
        let running = Family::<InterfaceLabels, Gauge>::default();
        registry.register(
            "mikrotik_interface_running",
            "Interface running status (1=running,0=down)",
            running.clone(),
        );
        let info = Family::<InterfaceInfoLabels, Gauge>::default();
        registry.register(
            "mikrotik_interface_info",
            "Static interface info (value=1)",
            info.clone(),
        );

        Self {
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
            rx_errors,
            tx_errors,
            running,
            info,
            prev: Arc::new(DashMap::new()),
            prev_info: Arc::new(DashMap::new()),
            info_last_seen: Arc::new(DashMap::new()),
            seeded_routers: Arc::new(DashMap::new()),
        }
    }

    pub(crate) fn update(
        &self,
        router_name: &str,
        interfaces: &[InterfaceStats],
        apply_counters: bool,
    ) {
        // Seed cumulative counters on the first counters-applying update for
        // this domain. Interfaces share the system/interfaces group, which
        // fails the whole router, so in practice this is the first snapshot,
        // but keeping the decision per-domain keeps the two counter domains
        // consistent and future-proof.
        let seed_cumulative = apply_counters && !self.seeded_routers.contains_key(router_name);
        let mut current_interface_info = HashMap::new();

        for iface in interfaces {
            let labels = InterfaceLabels {
                router: router_name.into(),
                id: iface.id.clone(),
            };
            let info_labels = InterfaceInfoLabels {
                router: router_name.into(),
                id: iface.id.clone(),
                name: iface.name.clone(),
                comment: iface.comment.clone(),
            };

            current_interface_info.insert(labels.clone(), info_labels.clone());

            self.process_counters(iface, &labels, apply_counters, seed_cumulative);
            self.process_gauges(iface, &labels);
            self.process_info(iface, &labels, &info_labels);
        }

        self.cleanup_stale(router_name, &current_interface_info);

        if apply_counters {
            self.seeded_routers.insert(router_name.into(), ());
        }
    }

    fn process_counters(
        &self,
        iface: &InterfaceStats,
        labels: &InterfaceLabels,
        apply_counters: bool,
        seed_cumulative: bool,
    ) {
        let previous = self.prev.get(labels).map(|entry| *entry.value());
        let required: [(&Family<InterfaceLabels, Counter>, u64, Option<u64>); 4] = [
            (&self.rx_bytes, iface.rx_bytes, previous.map(|s| s.rx_bytes)),
            (&self.tx_bytes, iface.tx_bytes, previous.map(|s| s.tx_bytes)),
            (
                &self.rx_packets,
                iface.rx_packets,
                previous.map(|s| s.rx_packets),
            ),
            (
                &self.tx_packets,
                iface.tx_packets,
                previous.map(|s| s.tx_packets),
            ),
        ];
        for (family, current, previous_value) in required {
            let counter = family.get_or_create(labels);
            if !apply_counters {
                continue;
            }
            if let Some(previous_value) = previous_value {
                counter.inc_by(crate::metrics::registry::counter_delta(
                    current,
                    previous_value,
                ));
            } else if previous.is_none() && seed_cumulative {
                counter.inc_by(current);
            }
        }

        self.process_optional_counter(
            &self.rx_errors,
            iface.rx_errors,
            labels,
            previous.and_then(|s| s.rx_errors),
            apply_counters,
            seed_cumulative,
        );
        self.process_optional_counter(
            &self.tx_errors,
            iface.tx_errors,
            labels,
            previous.and_then(|s| s.tx_errors),
            apply_counters,
            seed_cumulative,
        );
    }

    fn process_optional_counter(
        &self,
        family: &Family<InterfaceLabels, Counter>,
        current: Option<u64>,
        labels: &InterfaceLabels,
        previous: Option<u64>,
        apply_counters: bool,
        seed_cumulative: bool,
    ) {
        let Some(current) = current else {
            return;
        };
        let counter = family.get_or_create(labels);
        if !apply_counters {
            return;
        }
        match previous {
            Some(previous) => {
                counter.inc_by(crate::metrics::registry::counter_delta(current, previous));
            }
            // The field was previously unreported (`None`) for an existing
            // label: seed the lifetime count so a counter that appears later is
            // not silently lost as zero.
            None if self.prev.contains_key(labels) => {
                counter.inc_by(current);
            }
            None if seed_cumulative => {
                counter.inc_by(current);
            }
            None => {}
        }
    }

    fn process_gauges(&self, iface: &InterfaceStats, labels: &InterfaceLabels) {
        self.running
            .get_or_create(labels)
            .set(i64::from(iface.running));
    }

    fn process_info(
        &self,
        iface: &InterfaceStats,
        labels: &InterfaceLabels,
        info_labels: &InterfaceInfoLabels,
    ) {
        let now = Instant::now();
        self.info.get_or_create(info_labels).set(1);
        self.prev.insert(
            labels.clone(),
            InterfaceSnapshot {
                rx_bytes: iface.rx_bytes,
                tx_bytes: iface.tx_bytes,
                rx_packets: iface.rx_packets,
                tx_packets: iface.tx_packets,
                rx_errors: iface.rx_errors,
                tx_errors: iface.tx_errors,
            },
        );
        self.info_last_seen.insert(info_labels.clone(), now);
    }

    fn cleanup_stale(
        &self,
        router_name: &str,
        current_interface_info: &HashMap<InterfaceLabels, InterfaceInfoLabels>,
    ) {
        let mut prev_info_entry = self.prev_info.entry(router_name.into()).or_default();
        let prev_map = prev_info_entry.value_mut();

        for (labels, info_labels) in prev_map.iter() {
            if !current_interface_info.contains_key(labels) {
                self.rx_bytes.remove(labels);
                self.tx_bytes.remove(labels);
                self.rx_packets.remove(labels);
                self.tx_packets.remove(labels);
                self.rx_errors.remove(labels);
                self.tx_errors.remove(labels);
                self.running.remove(labels);
                self.prev.remove(labels);

                self.info.remove(info_labels);
                self.info_last_seen.remove(info_labels);
            } else if let Some(current_info) = current_interface_info.get(labels)
                && current_info != info_labels
            {
                self.info.get_or_create(info_labels).set(0);
            }
        }
        prev_map.clone_from(current_interface_info);
    }

    pub(crate) fn cleanup_expired_info(&self, now: Instant, ttl: std::time::Duration) {
        let stale: Vec<InterfaceInfoLabels> = self
            .info_last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();
        if !stale.is_empty() {
            let count = stale.len();
            for label in stale {
                self.info_last_seen.remove(&label);
                self.info.remove(&label);
            }
            tracing::debug!(
                expired = count,
                "Expired interface info labels via TTL cleanup"
            );
        }
    }

    pub(crate) fn cleanup_stale_router(&self, router_name: &str) {
        let stale: Vec<InterfaceLabels> = self
            .prev
            .iter()
            .filter(|entry| entry.key().router == router_name)
            .map(|entry| entry.key().clone())
            .collect();
        for label in stale {
            self.prev.remove(&label);
            self.rx_bytes.remove(&label);
            self.tx_bytes.remove(&label);
            self.rx_packets.remove(&label);
            self.tx_packets.remove(&label);
            self.rx_errors.remove(&label);
            self.tx_errors.remove(&label);
            self.running.remove(&label);
        }
        if let Some((_, map)) = self.prev_info.remove(router_name) {
            for info_label in map.values() {
                self.info.remove(info_label);
                self.info_last_seen.remove(info_label);
            }
        }
        self.seeded_routers.remove(router_name);
    }

    pub(crate) fn retain_active_last_seen(
        &self,
        active_routers: &std::collections::HashSet<String>,
    ) {
        self.info_last_seen.retain(|labels, _| {
            if active_routers.contains(&labels.router) {
                true
            } else {
                self.info.remove(labels);
                false
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::InterfaceStats;
    use crate::metrics::registry::MetricsRegistry;
    use crate::metrics::registry::test_support::*;

    #[test]
    fn test_new_registry_initializes_correctly() {
        let registry = MetricsRegistry::new();
        assert_eq!(
            registry
                .interface
                .rx_bytes
                .get_or_create(&crate::metrics::labels::InterfaceLabels {
                    router: "test".to_string(),
                    id: "*1".to_string(),
                })
                .get(),
            0
        );
    }

    #[tokio::test]
    async fn test_complete_empty_interfaces_remove_previous_series() {
        let registry = MetricsRegistry::new();
        let mut snapshot = make_router_metrics(
            "router1",
            vec![make_interface(
                "*1", "ether1", "WAN", 1, 2, 3, 4, 0, 0, true,
            )],
            make_system("7.10", "board", "1d"),
        );
        registry.update_metrics(&snapshot);
        snapshot.interfaces.clear();
        registry.update_metrics(&snapshot);
        assert!(registry.interface.prev.is_empty());
        assert!(
            !registry
                .encode_metrics()
                .await
                .unwrap()
                .lines()
                .any(|line| line.starts_with("mikrotik_interface_"))
        );
    }

    #[tokio::test]
    async fn test_update_metrics_first_time() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("*1", "ether1", "WAN", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d");
        let metrics = make_router_metrics("router1", vec![iface], system);

        registry.update_metrics(&metrics);

        let labels = crate::metrics::labels::InterfaceLabels {
            router: "router1".to_string(),
            id: "*1".to_string(),
        };
        assert_eq!(
            registry.interface.rx_bytes.get_or_create(&labels).get(),
            1000
        );
        assert_eq!(
            registry.interface.tx_bytes.get_or_create(&labels).get(),
            2000
        );
        assert_eq!(
            registry.interface.rx_packets.get_or_create(&labels).get(),
            10
        );
        assert_eq!(
            registry.interface.tx_packets.get_or_create(&labels).get(),
            20
        );
    }

    #[tokio::test]
    async fn test_update_metrics_with_deltas() {
        let registry = MetricsRegistry::new();

        let iface1 = make_interface("*1", "ether1", "WAN", 1000, 2000, 10, 20, 0, 0, true);
        let system1 = make_system("7.10", "RB750Gr3", "1d");
        let metrics1 = make_router_metrics("router1", vec![iface1], system1);
        registry.update_metrics(&metrics1);

        let iface2 = make_interface("*1", "ether1", "WAN", 1500, 2500, 15, 25, 0, 0, true);
        let system2 = make_system("7.10", "RB750Gr3", "1d");
        let metrics2 = make_router_metrics("router1", vec![iface2], system2);
        registry.update_metrics(&metrics2);

        let labels = crate::metrics::labels::InterfaceLabels {
            router: "router1".to_string(),
            id: "*1".to_string(),
        };
        assert_eq!(
            registry.interface.rx_bytes.get_or_create(&labels).get(),
            1500
        );
        assert_eq!(
            registry.interface.tx_bytes.get_or_create(&labels).get(),
            2500
        );
        assert_eq!(
            registry.interface.rx_packets.get_or_create(&labels).get(),
            15
        );
        assert_eq!(
            registry.interface.tx_packets.get_or_create(&labels).get(),
            25
        );
    }

    #[tokio::test]
    async fn test_update_metrics_baseline_skips_counters() {
        let registry = MetricsRegistry::new();

        let iface1 = make_interface("*1", "ether1", "WAN", 1000, 2000, 10, 20, 0, 0, true);
        let system1 = make_system("7.10", "RB750Gr3", "1d");
        let metrics1 = make_router_metrics("router1", vec![iface1], system1);
        registry.update_metrics_baseline(&metrics1);

        let labels = crate::metrics::labels::InterfaceLabels {
            router: "router1".to_string(),
            id: "*1".to_string(),
        };
        assert_eq!(registry.interface.rx_bytes.get_or_create(&labels).get(), 0);
        assert_eq!(registry.interface.tx_bytes.get_or_create(&labels).get(), 0);

        let iface2 = make_interface("*1", "ether1", "WAN", 1500, 2600, 15, 26, 0, 0, true);
        let system2 = make_system("7.10", "RB750Gr3", "1d");
        let metrics2 = make_router_metrics("router1", vec![iface2], system2);
        registry.update_metrics(&metrics2);

        assert_eq!(
            registry.interface.rx_bytes.get_or_create(&labels).get(),
            500
        );
        assert_eq!(
            registry.interface.tx_bytes.get_or_create(&labels).get(),
            600
        );
    }

    #[tokio::test]
    async fn test_update_metrics_counter_reset() {
        let registry = MetricsRegistry::new();

        let iface1 = make_interface("*1", "ether1", "WAN", 5000, 6000, 50, 60, 2, 3, true);
        let system1 = make_system("7.10", "RB750Gr3", "1d");
        let metrics1 = make_router_metrics("router1", vec![iface1], system1);
        registry.update_metrics(&metrics1);

        let iface2 = make_interface("*1", "ether1", "WAN", 1000, 2000, 10, 20, 0, 0, true);
        let system2 = make_system("7.10", "RB750Gr3", "1d");
        let metrics2 = make_router_metrics("router1", vec![iface2], system2);
        registry.update_metrics(&metrics2);

        let labels = crate::metrics::labels::InterfaceLabels {
            router: "router1".to_string(),
            id: "*1".to_string(),
        };
        assert_eq!(
            registry.interface.rx_bytes.get_or_create(&labels).get(),
            6000
        );
        assert_eq!(
            registry.interface.tx_bytes.get_or_create(&labels).get(),
            8000
        );
        assert_eq!(
            registry.interface.rx_packets.get_or_create(&labels).get(),
            60
        );
        assert_eq!(
            registry.interface.tx_packets.get_or_create(&labels).get(),
            80
        );
        assert_eq!(registry.interface.rx_errors.get_or_create(&labels).get(), 2);
        assert_eq!(registry.interface.tx_errors.get_or_create(&labels).get(), 3);
    }

    #[tokio::test]
    async fn test_interface_optional_counter_none_to_some_seeds_lifetime() {
        let registry = MetricsRegistry::new();
        let labels = crate::metrics::labels::InterfaceLabels {
            router: "router1".to_string(),
            id: "*1".to_string(),
        };

        let first = make_router_metrics(
            "router1",
            vec![InterfaceStats {
                id: "*1".into(),
                name: "ether1".into(),
                comment: "WAN".into(),
                rx_bytes: 1000,
                tx_bytes: 2000,
                rx_packets: 10,
                tx_packets: 20,
                rx_errors: None,
                tx_errors: None,
                running: true,
            }],
            make_system("7.10", "board", "1d"),
        );
        registry.update_metrics(&first);
        assert_eq!(registry.interface.rx_errors.get_or_create(&labels).get(), 0);

        let second = make_router_metrics(
            "router1",
            vec![InterfaceStats {
                id: "*1".into(),
                name: "ether1".into(),
                comment: "WAN".into(),
                rx_bytes: 1500,
                tx_bytes: 2600,
                rx_packets: 15,
                tx_packets: 26,
                rx_errors: Some(42),
                tx_errors: Some(17),
                running: true,
            }],
            make_system("7.10", "board", "1d"),
        );
        registry.update_metrics(&second);
        assert_eq!(
            registry.interface.rx_errors.get_or_create(&labels).get(),
            42,
            "a counter that appears after None seeds the lifetime count"
        );
        assert_eq!(
            registry.interface.tx_errors.get_or_create(&labels).get(),
            17
        );

        let third = make_router_metrics(
            "router1",
            vec![InterfaceStats {
                id: "*1".into(),
                name: "ether1".into(),
                comment: "WAN".into(),
                rx_bytes: 1600,
                tx_bytes: 2700,
                rx_packets: 16,
                tx_packets: 27,
                rx_errors: Some(45),
                tx_errors: Some(19),
                running: true,
            }],
            make_system("7.10", "board", "1d"),
        );
        registry.update_metrics(&third);
        assert_eq!(
            registry.interface.rx_errors.get_or_create(&labels).get(),
            45,
            "subsequent reports continue delta accumulation from the seeded value"
        );
    }

    #[tokio::test]
    async fn test_interface_optional_counter_fresh_label_on_seeded_router_stays_zero() {
        let registry = MetricsRegistry::new();
        let first = make_router_metrics(
            "router1",
            vec![make_interface(
                "*1", "ether1", "", 1000, 2000, 10, 20, 5, 6, true,
            )],
            make_system("7.10", "board", "1d"),
        );
        registry.update_metrics(&first);

        let labels = crate::metrics::labels::InterfaceLabels {
            router: "router1".to_string(),
            id: "*2".to_string(),
        };
        let second = make_router_metrics(
            "router1",
            vec![
                make_interface("*1", "ether1", "", 1500, 2500, 15, 25, 6, 7, true),
                InterfaceStats {
                    id: "*2".into(),
                    name: "ether2".into(),
                    comment: String::new(),
                    rx_bytes: 3000,
                    tx_bytes: 4000,
                    rx_packets: 30,
                    tx_packets: 40,
                    rx_errors: Some(8),
                    tx_errors: Some(9),
                    running: false,
                },
            ],
            make_system("7.10", "board", "1d"),
        );
        registry.update_metrics(&second);
        assert_eq!(registry.interface.rx_errors.get_or_create(&labels).get(), 0);
    }

    #[tokio::test]
    async fn test_interface_labels_with_metrics() {
        let registry = MetricsRegistry::new();

        let iface1 = make_interface("*1", "ether1", "WAN", 1000, 2000, 10, 20, 0, 0, true);
        let iface2 = make_interface("*2", "ether2", "LAN", 3000, 4000, 30, 40, 1, 2, false);
        let system = make_system("7.10", "RB750Gr3", "1d");
        let metrics = make_router_metrics("router1", vec![iface1, iface2], system);
        registry.update_metrics(&metrics);

        let labels1 = crate::metrics::labels::InterfaceLabels {
            router: "router1".to_string(),
            id: "*1".to_string(),
        };
        let labels2 = crate::metrics::labels::InterfaceLabels {
            router: "router1".to_string(),
            id: "*2".to_string(),
        };

        assert_eq!(
            registry.interface.rx_bytes.get_or_create(&labels1).get(),
            1000
        );
        assert_eq!(
            registry.interface.rx_bytes.get_or_create(&labels2).get(),
            3000
        );
        assert_eq!(registry.interface.running.get_or_create(&labels1).get(), 1);
        assert_eq!(registry.interface.running.get_or_create(&labels2).get(), 0);
    }
}
