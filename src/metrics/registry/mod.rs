// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Metrics registry and update logic

mod cleanup;
mod init;
mod scrape;
mod update;

use crate::metrics::labels::{
    ConntrackLabels, InterfaceLabels, RouterLabels, SystemInfoLabels, WireGuardPeerInfoLabels,
    WireGuardPeerLabels,
};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Clone, Copy)]
struct InterfaceSnapshot {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_errors: u64,
    tx_errors: u64,
}

#[derive(Clone)]
pub struct MetricsRegistry {
    registry: Arc<Mutex<Registry>>,
    // counters (delta-applied)
    interface_rx_bytes: Family<InterfaceLabels, Counter>,
    interface_tx_bytes: Family<InterfaceLabels, Counter>,
    interface_rx_packets: Family<InterfaceLabels, Counter>,
    interface_tx_packets: Family<InterfaceLabels, Counter>,
    interface_rx_errors: Family<InterfaceLabels, Counter>,
    interface_tx_errors: Family<InterfaceLabels, Counter>,
    // gauges
    interface_running: Family<InterfaceLabels, Gauge>,
    system_cpu_load: Family<RouterLabels, Gauge>,
    system_free_memory: Family<RouterLabels, Gauge>,
    system_total_memory: Family<RouterLabels, Gauge>,
    system_info: Family<SystemInfoLabels, Gauge>,
    system_uptime_seconds: Family<RouterLabels, Gauge>,
    // scrape status counters
    scrape_success: Family<RouterLabels, Counter>,
    scrape_errors: Family<RouterLabels, Counter>,
    // scrape timing metrics
    scrape_duration_milliseconds: Family<RouterLabels, Gauge>,
    scrape_last_success_timestamp_seconds: Family<RouterLabels, Gauge>,
    connection_consecutive_errors: Family<RouterLabels, Gauge>,
    collection_cycle_duration_milliseconds: Gauge,
    // connection pool metrics
    connection_pool_size: Gauge,
    connection_pool_active: Gauge,
    // connection tracking metrics
    connection_tracking_count: Family<ConntrackLabels, Gauge>,
    // WireGuard metrics
    wireguard_peer_rx_bytes: Family<WireGuardPeerLabels, Gauge>,
    wireguard_peer_tx_bytes: Family<WireGuardPeerLabels, Gauge>,
    wireguard_peer_latest_handshake: Family<WireGuardPeerLabels, Gauge>,
    wireguard_peer_info: Family<WireGuardPeerInfoLabels, Gauge>,
    prev_iface: Arc<Mutex<HashMap<InterfaceLabels, InterfaceSnapshot>>>,
    prev_conntrack: Arc<Mutex<HashMap<String, HashSet<ConntrackLabels>>>>,
    prev_system_info: Arc<Mutex<HashMap<String, SystemInfoLabels>>>,
    prev_wireguard_peers: Arc<Mutex<HashMap<String, HashSet<WireGuardPeerLabels>>>>,
    prev_wireguard_peer_info:
        Arc<Mutex<HashMap<String, HashMap<WireGuardPeerLabels, WireGuardPeerInfoLabels>>>>,
    conntrack_last_seen: Arc<Mutex<HashMap<ConntrackLabels, Instant>>>,
    wireguard_peer_last_seen: Arc<Mutex<HashMap<WireGuardPeerLabels, Instant>>>,
    wireguard_peer_info_last_seen: Arc<Mutex<HashMap<WireGuardPeerInfoLabels, Instant>>>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mikrotik::{ConnectionTrackingStats, InterfaceStats, RouterMetrics, SystemResource};

    fn make_router_metrics(
        router_name: &str,
        interfaces: Vec<InterfaceStats>,
        system: SystemResource,
    ) -> RouterMetrics {
        RouterMetrics {
            router_name: router_name.to_string(),
            interfaces,
            system,
            connection_tracking: Vec::new(),
            wireguard_interfaces: Vec::new(),
            wireguard_peers: Vec::new(),
        }
    }

    fn make_conntrack(
        src_address: &str,
        protocol: &str,
        connection_count: u64,
        ip_version: &str,
    ) -> ConnectionTrackingStats {
        ConnectionTrackingStats {
            src_address: src_address.to_string(),
            protocol: protocol.to_string(),
            connection_count,
            ip_version: ip_version.to_string(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_interface(
        name: &str,
        rx_bytes: u64,
        tx_bytes: u64,
        rx_packets: u64,
        tx_packets: u64,
        rx_errors: u64,
        tx_errors: u64,
        running: bool,
    ) -> InterfaceStats {
        InterfaceStats {
            name: name.to_string(),
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
            rx_errors,
            tx_errors,
            running,
        }
    }

    fn make_system(version: &str, board_name: &str, uptime: &str) -> SystemResource {
        SystemResource {
            uptime: uptime.to_string(),
            cpu_load: 10,
            free_memory: 1024 * 1024 * 512,
            total_memory: 1024 * 1024 * 1024,
            version: version.to_string(),
            board_name: board_name.to_string(),
        }
    }

    #[test]
    fn test_new_registry_initializes_correctly() {
        let registry = MetricsRegistry::new();
        assert_eq!(
            registry
                .interface_rx_bytes
                .get_or_create(&InterfaceLabels {
                    router: "test".to_string(),
                    interface: "ether1".to_string(),
                })
                .get(),
            0
        );
    }

    #[tokio::test]
    async fn test_update_metrics_first_time() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("ether1", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d");
        let metrics = make_router_metrics("router1", vec![iface], system);

        registry.update_metrics(&metrics).await;

        let labels = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether1".to_string(),
        };
        assert_eq!(registry.interface_rx_bytes.get_or_create(&labels).get(), 0);
        assert_eq!(registry.interface_tx_bytes.get_or_create(&labels).get(), 0);
        assert_eq!(
            registry.interface_rx_packets.get_or_create(&labels).get(),
            0
        );
        assert_eq!(
            registry.interface_tx_packets.get_or_create(&labels).get(),
            0
        );
    }

    #[tokio::test]
    async fn test_update_metrics_with_deltas() {
        let registry = MetricsRegistry::new();

        let iface1 = make_interface("ether1", 1000, 2000, 10, 20, 0, 0, true);
        let system1 = make_system("7.10", "RB750Gr3", "1d");
        let metrics1 = make_router_metrics("router1", vec![iface1], system1);
        registry.update_metrics(&metrics1).await;

        let iface2 = make_interface("ether1", 1500, 2500, 15, 25, 0, 0, true);
        let system2 = make_system("7.10", "RB750Gr3", "1d");
        let metrics2 = make_router_metrics("router1", vec![iface2], system2);
        registry.update_metrics(&metrics2).await;

        let labels = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether1".to_string(),
        };
        assert_eq!(
            registry.interface_rx_bytes.get_or_create(&labels).get(),
            500
        );
        assert_eq!(
            registry.interface_tx_bytes.get_or_create(&labels).get(),
            500
        );
        assert_eq!(
            registry.interface_rx_packets.get_or_create(&labels).get(),
            5
        );
        assert_eq!(
            registry.interface_tx_packets.get_or_create(&labels).get(),
            5
        );
    }

    #[tokio::test]
    async fn test_update_metrics_counter_reset() {
        let registry = MetricsRegistry::new();

        let iface1 = make_interface("ether1", 5000, 6000, 50, 60, 2, 3, true);
        let system1 = make_system("7.10", "RB750Gr3", "1d");
        let metrics1 = make_router_metrics("router1", vec![iface1], system1);
        registry.update_metrics(&metrics1).await;

        let iface2 = make_interface("ether1", 1000, 2000, 10, 20, 0, 0, true);
        let system2 = make_system("7.10", "RB750Gr3", "1d");
        let metrics2 = make_router_metrics("router1", vec![iface2], system2);
        registry.update_metrics(&metrics2).await;

        let labels = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether1".to_string(),
        };
        assert_eq!(registry.interface_rx_bytes.get_or_create(&labels).get(), 0);
        assert_eq!(registry.interface_tx_bytes.get_or_create(&labels).get(), 0);
        assert_eq!(registry.interface_rx_errors.get_or_create(&labels).get(), 0);
        assert_eq!(registry.interface_tx_errors.get_or_create(&labels).get(), 0);
    }

    #[tokio::test]
    async fn test_encode_metrics_contains_expected_names() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("ether1", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d");
        let metrics = make_router_metrics("router1", vec![iface], system);
        registry.update_metrics(&metrics).await;

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
        assert!(encoded.contains("interface=\"ether1\""));
    }

    #[tokio::test]
    async fn test_concurrent_updates() {
        let registry = std::sync::Arc::new(MetricsRegistry::new());

        let mut tasks = vec![];
        for i in 0..5 {
            let registry_clone = registry.clone();
            let task = tokio::spawn(async move {
                let iface = make_interface(
                    &format!("ether{}", i),
                    1000 * (i as u64 + 1),
                    2000 * (i as u64 + 1),
                    10 * (i as u64 + 1),
                    20 * (i as u64 + 1),
                    0,
                    0,
                    true,
                );
                let system = make_system("7.10", "RB750Gr3", "1d");
                let metrics = make_router_metrics(&format!("router{}", i), vec![iface], system);
                registry_clone.update_metrics(&metrics).await;
            });
            tasks.push(task);
        }

        for task in tasks {
            task.await.expect("Task failed");
        }

        let encoded = registry.encode_metrics().await.expect("Failed to encode");
        for i in 0..5 {
            assert!(encoded.contains(&format!("ether{}", i)));
            assert!(encoded.contains(&format!("router{}", i)));
        }
    }

    #[test]
    fn test_record_scrape_success_increments() {
        let registry = MetricsRegistry::new();
        let labels = RouterLabels {
            router: "router1".to_string(),
        };

        assert_eq!(registry.scrape_success.get_or_create(&labels).get(), 0);
        registry.record_scrape_success(&labels);
        assert_eq!(registry.scrape_success.get_or_create(&labels).get(), 1);
        registry.record_scrape_success(&labels);
        assert_eq!(registry.scrape_success.get_or_create(&labels).get(), 2);
    }

    #[test]
    fn test_record_scrape_error_increments() {
        let registry = MetricsRegistry::new();
        let labels = RouterLabels {
            router: "router1".to_string(),
        };

        assert_eq!(registry.scrape_errors.get_or_create(&labels).get(), 0);
        registry.record_scrape_error(&labels);
        assert_eq!(registry.scrape_errors.get_or_create(&labels).get(), 1);
        registry.record_scrape_error(&labels);
        assert_eq!(registry.scrape_errors.get_or_create(&labels).get(), 2);
    }

    #[test]
    fn test_update_pool_stats_sets_gauges() {
        let registry = MetricsRegistry::new();

        registry.update_pool_stats(10, 5);
        assert_eq!(registry.connection_pool_size.get(), 10);
        assert_eq!(registry.connection_pool_active.get(), 5);

        registry.update_pool_stats(20, 8);
        assert_eq!(registry.connection_pool_size.get(), 20);
        assert_eq!(registry.connection_pool_active.get(), 8);
    }

    #[test]
    fn test_record_collection_cycle_duration_sets_gauge() {
        let registry = MetricsRegistry::new();

        registry.record_collection_cycle_duration(0.012);
        assert_eq!(registry.collection_cycle_duration_milliseconds.get(), 12);

        registry.record_collection_cycle_duration(1.234);
        assert_eq!(registry.collection_cycle_duration_milliseconds.get(), 1234);
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
                .connection_consecutive_errors
                .get_or_create(&labels)
                .get(),
            0
        );

        registry.update_connection_errors(&labels, 3);
        assert_eq!(
            registry
                .connection_consecutive_errors
                .get_or_create(&labels)
                .get(),
            3
        );
    }

    #[tokio::test]
    async fn test_interface_labels_with_metrics() {
        let registry = MetricsRegistry::new();

        let iface1 = make_interface("ether1", 1000, 2000, 10, 20, 0, 0, true);
        let iface2 = make_interface("ether2", 3000, 4000, 30, 40, 1, 2, false);
        let system = make_system("7.10", "RB750Gr3", "1d");
        let metrics = make_router_metrics("router1", vec![iface1, iface2], system);
        registry.update_metrics(&metrics).await;

        let labels1 = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether1".to_string(),
        };
        let labels2 = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether2".to_string(),
        };

        assert_eq!(registry.interface_rx_bytes.get_or_create(&labels1).get(), 0);
        assert_eq!(registry.interface_rx_bytes.get_or_create(&labels2).get(), 0);
        assert_eq!(registry.interface_running.get_or_create(&labels1).get(), 1);
        assert_eq!(registry.interface_running.get_or_create(&labels2).get(), 0);
    }

    #[tokio::test]
    async fn test_system_metrics_gauge_values() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("ether1", 1000, 2000, 10, 20, 0, 0, true);
        let system = SystemResource {
            uptime: "1d2h3m4s".to_string(),
            cpu_load: 50,
            free_memory: 512 * 1024 * 1024,
            total_memory: 1024 * 1024 * 1024,
            version: "7.10".to_string(),
            board_name: "RB750Gr3".to_string(),
        };
        let metrics = make_router_metrics("router1", vec![iface], system);
        registry.update_metrics(&metrics).await;

        let router_label = RouterLabels {
            router: "router1".to_string(),
        };

        assert_eq!(
            registry.system_cpu_load.get_or_create(&router_label).get(),
            50
        );
        assert_eq!(
            registry
                .system_free_memory
                .get_or_create(&router_label)
                .get(),
            512 * 1024 * 1024
        );
        assert_eq!(
            registry
                .system_total_memory
                .get_or_create(&router_label)
                .get(),
            1024 * 1024 * 1024
        );
    }

    #[tokio::test]
    async fn test_connection_tracking_multi_router() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("ether1", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d2h3m4s");

        // First update for router1 with TCP connections
        let mut metrics1 = make_router_metrics("router1", vec![iface.clone()], system.clone());
        metrics1.connection_tracking = vec![
            make_conntrack("192.168.1.1", "tcp", 100, "ipv4"),
            make_conntrack("192.168.1.1", "udp", 50, "ipv4"),
        ];
        registry.update_metrics(&metrics1).await;

        // First update for router2 with different connections
        let mut metrics2 = make_router_metrics("router2", vec![iface.clone()], system.clone());
        metrics2.connection_tracking = vec![
            make_conntrack("10.0.0.1", "tcp", 200, "ipv4"),
            make_conntrack("10.0.0.1", "icmp", 10, "ipv4"),
        ];
        registry.update_metrics(&metrics2).await;

        // Check that both routers have their metrics
        let labels1_tcp = ConntrackLabels {
            router: "router1".to_string(),
            src_address: "192.168.1.1".to_string(),
            protocol: "tcp".to_string(),
            ip_version: "ipv4".to_string(),
        };
        let labels1_udp = ConntrackLabels {
            router: "router1".to_string(),
            src_address: "192.168.1.1".to_string(),
            protocol: "udp".to_string(),
            ip_version: "ipv4".to_string(),
        };
        let labels2_tcp = ConntrackLabels {
            router: "router2".to_string(),
            src_address: "10.0.0.1".to_string(),
            protocol: "tcp".to_string(),
            ip_version: "ipv4".to_string(),
        };
        let labels2_icmp = ConntrackLabels {
            router: "router2".to_string(),
            src_address: "10.0.0.1".to_string(),
            protocol: "icmp".to_string(),
            ip_version: "ipv4".to_string(),
        };

        assert_eq!(
            registry
                .connection_tracking_count
                .get_or_create(&labels1_tcp)
                .get(),
            100
        );
        assert_eq!(
            registry
                .connection_tracking_count
                .get_or_create(&labels1_udp)
                .get(),
            50
        );
        assert_eq!(
            registry
                .connection_tracking_count
                .get_or_create(&labels2_tcp)
                .get(),
            200
        );
        assert_eq!(
            registry
                .connection_tracking_count
                .get_or_create(&labels2_icmp)
                .get(),
            10
        );

        // Second update for router1: remove UDP, keep TCP
        metrics1.connection_tracking = vec![make_conntrack("192.168.1.1", "tcp", 150, "ipv4")];
        registry.update_metrics(&metrics1).await;

        // Check that router1's UDP was reset to 0, but TCP updated
        assert_eq!(
            registry
                .connection_tracking_count
                .get_or_create(&labels1_tcp)
                .get(),
            150
        );
        assert_eq!(
            registry
                .connection_tracking_count
                .get_or_create(&labels1_udp)
                .get(),
            0
        );

        // CRITICAL: Check that router2's metrics are NOT affected
        assert_eq!(
            registry
                .connection_tracking_count
                .get_or_create(&labels2_tcp)
                .get(),
            200
        );
        assert_eq!(
            registry
                .connection_tracking_count
                .get_or_create(&labels2_icmp)
                .get(),
            10
        );
    }

    #[tokio::test]
    async fn test_system_info_stale_label_reset_on_version_change() {
        let registry = MetricsRegistry::new();

        let iface = make_interface("ether1", 1000, 2000, 10, 20, 0, 0, true);
        let system_v1 = SystemResource {
            uptime: "1d".to_string(),
            cpu_load: 10,
            free_memory: 512 * 1024 * 1024,
            total_memory: 1024 * 1024 * 1024,
            version: "7.10".to_string(),
            board_name: "RB750Gr3".to_string(),
        };
        let metrics_v1 = make_router_metrics("router1", vec![iface.clone()], system_v1);
        registry.update_metrics(&metrics_v1).await;

        let old_labels = SystemInfoLabels {
            router: "router1".to_string(),
            version: "7.10".to_string(),
            board: "RB750Gr3".to_string(),
        };
        assert_eq!(registry.system_info.get_or_create(&old_labels).get(), 1);

        let system_v2 = SystemResource {
            uptime: "1d".to_string(),
            cpu_load: 10,
            free_memory: 512 * 1024 * 1024,
            total_memory: 1024 * 1024 * 1024,
            version: "7.11".to_string(),
            board_name: "RB750Gr3".to_string(),
        };
        let metrics_v2 = make_router_metrics("router1", vec![iface], system_v2);
        registry.update_metrics(&metrics_v2).await;

        let new_labels = SystemInfoLabels {
            router: "router1".to_string(),
            version: "7.11".to_string(),
            board: "RB750Gr3".to_string(),
        };
        assert_eq!(
            registry.system_info.get_or_create(&old_labels).get(),
            0,
            "Old system_info label should be reset to 0"
        );
        assert_eq!(
            registry.system_info.get_or_create(&new_labels).get(),
            1,
            "New system_info label should be 1"
        );
    }

    #[tokio::test]
    async fn test_system_info_no_reset_when_unchanged() {
        let registry = MetricsRegistry::new();

        let iface = make_interface("ether1", 1000, 2000, 10, 20, 0, 0, true);
        let system = SystemResource {
            uptime: "1d".to_string(),
            cpu_load: 10,
            free_memory: 512 * 1024 * 1024,
            total_memory: 1024 * 1024 * 1024,
            version: "7.10".to_string(),
            board_name: "RB750Gr3".to_string(),
        };
        let metrics = make_router_metrics("router1", vec![iface.clone()], system.clone());
        registry.update_metrics(&metrics).await;
        registry.update_metrics(&metrics).await;

        let labels = SystemInfoLabels {
            router: "router1".to_string(),
            version: "7.10".to_string(),
            board: "RB750Gr3".to_string(),
        };
        assert_eq!(
            registry.system_info.get_or_create(&labels).get(),
            1,
            "system_info should stay 1 when version/board unchanged"
        );
    }
}
