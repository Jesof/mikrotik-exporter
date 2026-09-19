// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Metrics registry: registration, update, encoding, and cleanup logic.

mod cleanup;
mod init;
mod scrape;
mod update;

pub(crate) mod domains;

#[cfg(test)]
pub(crate) mod test_support;

use dashmap::DashMap;
use prometheus_client::registry::Registry;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::metrics::registry::domains::{
    certificate::CertificateDomain, conntrack::ConntrackDomain, firewall::FirewallDomain,
    interface::InterfaceDomain, pool::PoolDomain, scrape::ScrapeDomain, system::SystemDomain,
    wireguard::WireGuardDomain,
};

#[derive(Clone)]
pub struct MetricsRegistry {
    registry: Arc<Mutex<Registry>>,
    interface: InterfaceDomain,
    system: SystemDomain,
    conntrack: ConntrackDomain,
    wireguard: WireGuardDomain,
    certificate: CertificateDomain,
    firewall: FirewallDomain,
    scrape: ScrapeDomain,
    pool: PoolDomain,
    known_routers: Arc<DashMap<String, ()>>,
    collected_routers: Arc<DashMap<String, ()>>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::RouterLabels;
    use crate::mikrotik::{
        CollectionStatus, CollectionStatusParts, FetchState, SystemResource, WireGuardPeerStats,
    };

    #[test]
    fn test_partial_group_status_does_not_advance_freshness() {
        let registry = MetricsRegistry::new();
        let labels = RouterLabels {
            router: "router1".into(),
        };
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

    #[tokio::test]
    async fn test_cleanup_removes_initialized_router_without_successful_snapshot() {
        let registry = MetricsRegistry::new();
        registry.initialize_router_metrics(&RouterLabels {
            router: "never-connected".into(),
        });
        registry.cleanup_stale_routers(&std::collections::HashSet::new());
        assert!(
            !registry
                .encode_metrics()
                .await
                .unwrap()
                .contains("never-connected")
        );
    }

    #[tokio::test]
    async fn test_router_removal_cleans_superseded_metadata() {
        let registry = MetricsRegistry::new();
        let mut snapshot = make_router_metrics(
            "router1",
            vec![make_interface(
                "*1", "ether1", "old", 1, 2, 3, 4, 0, 0, true,
            )],
            make_system("7.10", "board", "1d"),
        );
        snapshot.wireguard_peers = vec![WireGuardPeerStats {
            id: "*1".into(),
            comment: "old".into(),
            ..Default::default()
        }];
        registry.update_metrics(&snapshot);
        snapshot.interfaces[0].comment = "new".into();
        snapshot.wireguard_peers[0].comment = "new".into();
        snapshot.firewall_rules[0].comment = "new".into();
        registry.update_metrics(&snapshot);
        registry.cleanup_stale_routers(&std::collections::HashSet::new());
        assert!(!registry.encode_metrics().await.unwrap().contains("router1"));
        assert!(registry.interface.info_last_seen.is_empty());
        assert!(registry.wireguard.peer_info_last_seen.is_empty());
        assert!(registry.firewall.rule_info_last_seen.is_empty());
    }

    #[tokio::test]
    async fn test_recovery_after_scrape_error_restores_system_and_interface_metrics() {
        let registry = MetricsRegistry::new();

        let iface_before = make_interface("*1", "ether1", "WAN", 1000, 2000, 10, 20, 0, 0, false);
        let system_before = SystemResource {
            uptime: "1d".to_string(),
            cpu_load: 10,
            free_memory: 512 * 1024 * 1024,
            total_memory: 1024 * 1024 * 1024,
            version: "7.10".to_string(),
            board_name: "RB750Gr3".to_string(),
        };
        let metrics_before = make_router_metrics("router1", vec![iface_before], system_before);
        registry.update_metrics(&metrics_before);

        let router_label = RouterLabels {
            router: "router1".to_string(),
        };
        let start = std::time::Instant::now();
        assert!(
            registry
                .record_scrape_success_and_check_gap(
                    &router_label,
                    start.into(),
                    std::time::Duration::from_secs(30)
                )
                .is_none()
        );

        let iface_labels = crate::metrics::labels::InterfaceLabels {
            router: "router1".to_string(),
            id: "*1".to_string(),
        };
        assert_eq!(
            registry
                .interface
                .running
                .get_or_create(&iface_labels)
                .get(),
            0
        );
        assert!(
            (registry.system.cpu_load.get_or_create(&router_label).get() - 0.1).abs()
                < f64::EPSILON
        );
        assert_eq!(
            registry
                .interface
                .rx_bytes
                .get_or_create(&iface_labels)
                .get(),
            1000
        );

        registry.record_scrape_error(&router_label);

        let iface_after = make_interface("*1", "ether1", "WAN", 1500, 2600, 15, 26, 0, 0, true);
        let system_after = SystemResource {
            uptime: "1d1h".to_string(),
            cpu_load: 55,
            free_memory: 256 * 1024 * 1024,
            total_memory: 1024 * 1024 * 1024,
            version: "7.10".to_string(),
            board_name: "RB750Gr3".to_string(),
        };
        let metrics_after = make_router_metrics("router1", vec![iface_after], system_after);

        let recovered_at = start + std::time::Duration::from_secs(31);
        assert!(
            registry
                .record_scrape_success_and_check_gap(
                    &router_label,
                    recovered_at.into(),
                    std::time::Duration::from_secs(30),
                )
                .is_some(),
            "recovery after error should trigger baseline mode"
        );
        registry.update_metrics_baseline(&metrics_after);

        assert_eq!(
            registry
                .interface
                .running
                .get_or_create(&iface_labels)
                .get(),
            1
        );
        assert!(
            (registry.system.cpu_load.get_or_create(&router_label).get() - 0.55).abs()
                < f64::EPSILON
        );
        assert_eq!(
            registry
                .interface
                .rx_bytes
                .get_or_create(&iface_labels)
                .get(),
            1000,
            "baseline update must not increment counters"
        );

        let iface_next = make_interface("*1", "ether1", "WAN", 1700, 2800, 17, 28, 0, 0, true);
        let system_next = SystemResource {
            uptime: "1d2h".to_string(),
            cpu_load: 60,
            free_memory: 220 * 1024 * 1024,
            total_memory: 1024 * 1024 * 1024,
            version: "7.10".to_string(),
            board_name: "RB750Gr3".to_string(),
        };
        let metrics_next = make_router_metrics("router1", vec![iface_next], system_next);
        registry.update_metrics(&metrics_next);

        assert_eq!(
            registry
                .interface
                .rx_bytes
                .get_or_create(&iface_labels)
                .get(),
            1200
        );
        assert!(
            (registry.system.cpu_load.get_or_create(&router_label).get() - 0.6).abs()
                < f64::EPSILON
        );
    }

    #[tokio::test]
    async fn test_encode_metrics_contains_expected_names() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("*1", "ether1", "", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d");
        let metrics = make_router_metrics("router1", vec![iface], system);
        registry.update_metrics(&metrics);

        let router_label = RouterLabels {
            router: "router1".to_string(),
        };
        registry.record_scrape_success(&router_label);
        registry.record_scrape_error(&router_label);

        let encoded = registry.encode_metrics().await.expect("Failed to encode");

        assert!(encoded.contains("mikrotik_interface_rx_bytes_total"));
        assert!(encoded.contains("mikrotik_interface_tx_bytes_total"));
        assert!(encoded.contains("mikrotik_interface_running"));
        assert!(encoded.contains("mikrotik_system_cpu_load"));
        assert!(encoded.contains("mikrotik_system_free_memory_bytes"));
        assert!(encoded.contains("mikrotik_scrape_success_total"));
        assert!(encoded.contains("mikrotik_scrape_errors_total"));
        assert!(encoded.contains("router=\"router1\""));
        assert!(encoded.contains("id=\"*1\""));
    }

    #[tokio::test]
    async fn test_concurrent_updates() {
        let registry = std::sync::Arc::new(MetricsRegistry::new());

        let mut tasks = vec![];
        for i in 0u64..5 {
            let registry_clone = registry.clone();
            let task = tokio::spawn(async move {
                let iface = make_interface(
                    &format!("*{i}"),
                    &format!("ether{i}"),
                    "",
                    1000 * (i + 1),
                    2000 * (i + 1),
                    10 * (i + 1),
                    20 * (i + 1),
                    0,
                    0,
                    true,
                );
                let system = make_system("7.10", "RB750Gr3", "1d");
                let metrics = make_router_metrics(&format!("router{i}"), vec![iface], system);
                registry_clone.update_metrics(&metrics);
            });
            tasks.push(task);
        }

        for task in tasks {
            task.await.expect("Task failed");
        }

        let encoded = registry.encode_metrics().await.expect("Failed to encode");
        for i in 0..5 {
            assert!(encoded.contains(&format!("router{i}")));
            assert!(encoded.contains(&format!("id=\"*{i}\"")));
        }
    }
}
