// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Metrics registry and update logic

use crate::mikrotik::RouterMetrics;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

use super::labels::{
    ConntrackLabels, InterfaceLabels, RouterLabels, SystemInfoLabels, WireGuardInterfaceLabels,
    WireGuardPeerLabels,
};
use super::parsers::parse_uptime_to_seconds;

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
    prev_iface: Arc<Mutex<HashMap<InterfaceLabels, InterfaceSnapshot>>>,
    prev_conntrack: Arc<Mutex<HashMap<String, HashSet<ConntrackLabels>>>>,
    prev_system_info: Arc<Mutex<HashMap<String, SystemInfoLabels>>>,
}

impl MetricsRegistry {
    #[allow(clippy::similar_names)] // rx/tx naming pattern is intentional
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let interface_rx_bytes = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_rx_bytes",
            "Received bytes on interface",
            interface_rx_bytes.clone(),
        );
        let interface_tx_bytes = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_tx_bytes",
            "Transmitted bytes on interface",
            interface_tx_bytes.clone(),
        );
        let interface_rx_packets = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_rx_packets",
            "Received packets on interface",
            interface_rx_packets.clone(),
        );
        let interface_tx_packets = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_tx_packets",
            "Transmitted packets on interface",
            interface_tx_packets.clone(),
        );
        let interface_rx_errors = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_rx_errors",
            "Receive errors on interface",
            interface_rx_errors.clone(),
        );
        let interface_tx_errors = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_tx_errors",
            "Transmit errors on interface",
            interface_tx_errors.clone(),
        );
        let interface_running = Family::<InterfaceLabels, Gauge>::default();
        registry.register(
            "mikrotik_interface_running",
            "Interface running status (1=running,0=down)",
            interface_running.clone(),
        );

        let system_cpu_load = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_cpu_load",
            "CPU load percentage",
            system_cpu_load.clone(),
        );
        let system_free_memory = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_free_memory_bytes",
            "Free memory bytes",
            system_free_memory.clone(),
        );
        let system_total_memory = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_total_memory_bytes",
            "Total memory bytes",
            system_total_memory.clone(),
        );
        let system_info = Family::<SystemInfoLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_info",
            "Static system info (value=1)",
            system_info.clone(),
        );
        let system_uptime_seconds = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_uptime_seconds",
            "System uptime in seconds",
            system_uptime_seconds.clone(),
        );
        let scrape_success = Family::<RouterLabels, Counter>::default();
        registry.register(
            "mikrotik_scrape_success",
            "Successful scrape cycles per router",
            scrape_success.clone(),
        );
        let scrape_errors = Family::<RouterLabels, Counter>::default();
        registry.register(
            "mikrotik_scrape_errors",
            "Failed scrape cycles per router",
            scrape_errors.clone(),
        );
        let scrape_duration_milliseconds = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_scrape_duration_milliseconds",
            "Duration of last scrape in milliseconds",
            scrape_duration_milliseconds.clone(),
        );
        let scrape_last_success_timestamp_seconds = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_scrape_last_success_timestamp_seconds",
            "Unix timestamp of last successful scrape",
            scrape_last_success_timestamp_seconds.clone(),
        );
        let connection_consecutive_errors = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_connection_consecutive_errors",
            "Number of consecutive connection errors",
            connection_consecutive_errors.clone(),
        );
        let collection_cycle_duration_milliseconds = Gauge::default();
        registry.register(
            "mikrotik_collection_cycle_duration_milliseconds",
            "Duration of full collection cycle in milliseconds",
            collection_cycle_duration_milliseconds.clone(),
        );
        let connection_pool_size = Gauge::default();
        registry.register(
            "mikrotik_connection_pool_size",
            "Total number of connections in pool",
            connection_pool_size.clone(),
        );
        let connection_pool_active = Gauge::default();
        registry.register(
            "mikrotik_connection_pool_active",
            "Number of active connections in pool",
            connection_pool_active.clone(),
        );
        let connection_tracking_count = Family::<ConntrackLabels, Gauge>::default();
        registry.register(
            "mikrotik_connection_tracking_count",
            "Number of tracked connections per source address and protocol",
            connection_tracking_count.clone(),
        );

        // WireGuard metrics

        let wireguard_peer_rx_bytes = Family::<WireGuardPeerLabels, Gauge>::default();
        registry.register(
            "mikrotik_wireguard_peer_rx_bytes",
            "Bytes received from WireGuard peer",
            wireguard_peer_rx_bytes.clone(),
        );

        let wireguard_peer_tx_bytes = Family::<WireGuardPeerLabels, Gauge>::default();
        registry.register(
            "mikrotik_wireguard_peer_tx_bytes",
            "Bytes transmitted to WireGuard peer",
            wireguard_peer_tx_bytes.clone(),
        );

        let wireguard_peer_latest_handshake = Family::<WireGuardPeerLabels, Gauge>::default();
        registry.register(
            "mikrotik_wireguard_peer_latest_handshake",
            "Unix timestamp of last handshake with WireGuard peer",
            wireguard_peer_latest_handshake.clone(),
        );

        Self {
            registry: Arc::new(Mutex::new(registry)),
            interface_rx_bytes,
            interface_tx_bytes,
            interface_rx_packets,
            interface_tx_packets,
            interface_rx_errors,
            interface_tx_errors,
            interface_running,
            system_cpu_load,
            system_free_memory,
            system_total_memory,
            system_info,
            system_uptime_seconds,
            scrape_success,
            scrape_errors,
            scrape_duration_milliseconds,
            scrape_last_success_timestamp_seconds,
            connection_consecutive_errors,
            collection_cycle_duration_milliseconds,
            connection_pool_size,
            connection_pool_active,
            connection_tracking_count,
            wireguard_peer_rx_bytes,
            wireguard_peer_tx_bytes,
            wireguard_peer_latest_handshake,
            prev_iface: Arc::new(Mutex::new(HashMap::new())),
            prev_conntrack: Arc::new(Mutex::new(HashMap::new())),
            prev_system_info: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Update metrics from collected router data
    ///
    /// This method performs delta calculations for counter metrics (rx/tx bytes/packets)
    /// using the previous snapshot stored in `prev_iface`.
    ///
    /// # Router Name Uniqueness
    ///
    /// **CRITICAL**: This method assumes router names are unique. If two routers have the same name,
    /// their interface metrics will collide in the `prev_iface` HashMap, causing incorrect
    /// delta calculations and data corruption. The configuration layer enforces this requirement.
    ///
    /// # Arguments
    /// * `metrics` - The collected metrics from a router
    #[allow(clippy::similar_names)] // rx/tx naming pattern is intentional and clear
    pub async fn update_metrics(&self, metrics: &RouterMetrics) {
        {
            let mut prev = self.prev_iface.lock().await;
            for iface in &metrics.interfaces {
                let labels = InterfaceLabels {
                    router: metrics.router_name.clone(),
                    interface: iface.name.clone(),
                };
                let snapshot = prev.get(&labels).copied().unwrap_or(InterfaceSnapshot {
                    rx_bytes: iface.rx_bytes,
                    tx_bytes: iface.tx_bytes,
                    rx_packets: iface.rx_packets,
                    tx_packets: iface.tx_packets,
                    rx_errors: iface.rx_errors,
                    tx_errors: iface.tx_errors,
                });
                let dx_rx_bytes = iface.rx_bytes.saturating_sub(snapshot.rx_bytes);
                let dx_tx_bytes = iface.tx_bytes.saturating_sub(snapshot.tx_bytes);
                let dx_rx_packets = iface.rx_packets.saturating_sub(snapshot.rx_packets);
                let dx_tx_packets = iface.tx_packets.saturating_sub(snapshot.tx_packets);
                let dx_rx_errors = iface.rx_errors.saturating_sub(snapshot.rx_errors);
                let dx_tx_errors = iface.tx_errors.saturating_sub(snapshot.tx_errors);
                self.interface_rx_bytes
                    .get_or_create(&labels)
                    .inc_by(dx_rx_bytes);
                self.interface_tx_bytes
                    .get_or_create(&labels)
                    .inc_by(dx_tx_bytes);
                self.interface_rx_packets
                    .get_or_create(&labels)
                    .inc_by(dx_rx_packets);
                self.interface_tx_packets
                    .get_or_create(&labels)
                    .inc_by(dx_tx_packets);
                self.interface_rx_errors
                    .get_or_create(&labels)
                    .inc_by(dx_rx_errors);
                self.interface_tx_errors
                    .get_or_create(&labels)
                    .inc_by(dx_tx_errors);
                self.interface_running
                    .get_or_create(&labels)
                    .set(i64::from(iface.running));
                prev.insert(
                    labels,
                    InterfaceSnapshot {
                        rx_bytes: iface.rx_bytes,
                        tx_bytes: iface.tx_bytes,
                        rx_packets: iface.rx_packets,
                        tx_packets: iface.tx_packets,
                        rx_errors: iface.rx_errors,
                        tx_errors: iface.tx_errors,
                    },
                );
            }
        }

        let router_label = RouterLabels {
            router: metrics.router_name.clone(),
        };
        #[allow(clippy::cast_possible_wrap)]
        {
            self.system_cpu_load
                .get_or_create(&router_label)
                .set(metrics.system.cpu_load as i64);
            self.system_free_memory
                .get_or_create(&router_label)
                .set(metrics.system.free_memory as i64);
            self.system_total_memory
                .get_or_create(&router_label)
                .set(metrics.system.total_memory as i64);
            // parse uptime string to seconds
            let uptime_secs = parse_uptime_to_seconds(&metrics.system.uptime);
            self.system_uptime_seconds
                .get_or_create(&router_label)
                .set(uptime_secs as i64);
        }
        let info_labels = SystemInfoLabels {
            router: metrics.router_name.clone(),
            version: metrics.system.version.clone(),
            board: metrics.system.board_name.clone(),
        };
        {
            let mut prev = self.prev_system_info.lock().await;
            if let Some(old) = prev.get(&metrics.router_name) {
                if *old != info_labels {
                    self.system_info.get_or_create(old).set(0);
                }
            }
            prev.insert(metrics.router_name.clone(), info_labels.clone());
        }
        self.system_info.get_or_create(&info_labels).set(1);

        // Update connection tracking metrics
        let mut current_conntrack = HashSet::new();
        for ct in &metrics.connection_tracking {
            let ct_labels = ConntrackLabels {
                router: metrics.router_name.clone(),
                src_address: ct.src_address.clone(),
                protocol: ct.protocol.clone(),
                ip_version: ct.ip_version.clone(),
            };
            current_conntrack.insert(ct_labels.clone());
            #[allow(clippy::cast_possible_wrap)]
            self.connection_tracking_count
                .get_or_create(&ct_labels)
                .set(ct.connection_count as i64);
        }
        {
            let mut prev_map = self.prev_conntrack.lock().await;
            let prev_labels = prev_map
                .entry(metrics.router_name.clone())
                .or_insert_with(HashSet::new);
            for stale in prev_labels.difference(&current_conntrack) {
                self.connection_tracking_count.get_or_create(stale).set(0);
            }
            *prev_labels = current_conntrack;
        }

        // Update WireGuard interface metrics
        for wg_iface in &metrics.wireguard_interfaces {
            let _wg_labels = WireGuardInterfaceLabels {
                router: metrics.router_name.clone(),
                interface: wg_iface.name.clone(),
            };
            // Note: We're no longer updating wireguard_interface_enabled metric
            // as it duplicates information available in mikrotik_interface_running
        }

        // Update WireGuard peer metrics
        for wg_peer in &metrics.wireguard_peers {
            let endpoint = wg_peer
                .endpoint
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let wg_peer_labels = WireGuardPeerLabels {
                router: metrics.router_name.clone(),
                interface: wg_peer.interface.clone(),
                name: wg_peer.name.clone(),
                allowed_address: wg_peer.allowed_address.clone(),
                endpoint,
            };
            #[allow(clippy::cast_possible_wrap)]
            {
                self.wireguard_peer_rx_bytes
                    .get_or_create(&wg_peer_labels)
                    .set(wg_peer.rx_bytes as i64);
                self.wireguard_peer_tx_bytes
                    .get_or_create(&wg_peer_labels)
                    .set(wg_peer.tx_bytes as i64);
                if let Some(timestamp) = wg_peer.latest_handshake {
                    self.wireguard_peer_latest_handshake
                        .get_or_create(&wg_peer_labels)
                        .set(timestamp as i64);
                }
            }
        }
    }

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

    /// Clean up stale interface metrics for interfaces that no longer exist
    ///
    /// This method removes old interface snapshots from the prev_iface HashMap
    /// to prevent unbounded memory growth when interfaces are dynamically added/removed.
    ///
    /// # Arguments
    /// * `current_interfaces` - Set of currently active interface labels
    pub async fn cleanup_stale_interfaces(
        &self,
        current_interfaces: &std::collections::HashSet<InterfaceLabels>,
    ) {
        let mut prev = self.prev_iface.lock().await;
        let before_count = prev.len();
        prev.retain(|labels, _| current_interfaces.contains(labels));
        let after_count = prev.len();
        let removed = before_count - after_count;
        if removed > 0 {
            tracing::debug!("Cleaned up {} stale interface snapshots", removed);
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mikrotik::{ConnectionTrackingStats, InterfaceStats, SystemResource};

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

        let encoded = registry.encode_metrics().await.expect("Failed to encode");

        assert!(encoded.contains("mikrotik_interface_rx_bytes"));
        assert!(encoded.contains("mikrotik_interface_tx_bytes"));
        assert!(encoded.contains("mikrotik_interface_running"));
        assert!(encoded.contains("mikrotik_system_cpu_load"));
        assert!(encoded.contains("mikrotik_system_free_memory_bytes"));
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
