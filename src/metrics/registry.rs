// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Metrics registry and update logic

use crate::mikrotik::RouterMetrics;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::labels::{InterfaceLabels, RouterLabels, SystemInfoLabels};
use super::parsers::parse_uptime_to_seconds;

/// Snapshot of interface counters (`rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`, `rx_errors`, `tx_errors`)
type InterfaceSnapshot = (u64, u64, u64, u64, u64, u64);

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
    scrape_duration_seconds: Family<RouterLabels, Gauge>,
    scrape_last_success_timestamp_seconds: Family<RouterLabels, Gauge>,
    connection_consecutive_errors: Family<RouterLabels, Gauge>,
    // connection pool metrics
    connection_pool_size: Gauge,
    connection_pool_active: Gauge,
    // previous snapshot for counters
    prev_iface: Arc<Mutex<std::collections::HashMap<InterfaceLabels, InterfaceSnapshot>>>,
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
        let scrape_duration_seconds = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_scrape_duration_milliseconds",
            "Duration of last scrape in milliseconds",
            scrape_duration_seconds.clone(),
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
            scrape_duration_seconds,
            scrape_last_success_timestamp_seconds,
            connection_consecutive_errors,
            connection_pool_size,
            connection_pool_active,
            prev_iface: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    #[allow(clippy::similar_names)] // rx/tx naming pattern is intentional and clear
    pub async fn update_metrics(&self, metrics: &RouterMetrics) {
        {
            let mut prev = self.prev_iface.lock().await;
            for iface in &metrics.interfaces {
                let labels = InterfaceLabels {
                    router: metrics.router_name.clone(),
                    interface: iface.name.clone(),
                };
                let (prx, ptx, prxp, ptxp, prxe, ptxe) = prev.get(&labels).copied().unwrap_or((
                    iface.rx_bytes,
                    iface.tx_bytes,
                    iface.rx_packets,
                    iface.tx_packets,
                    iface.rx_errors,
                    iface.tx_errors,
                ));
                // compute deltas (handle reset)
                let dx_rx_bytes = iface.rx_bytes.saturating_sub(prx);
                let dx_tx_bytes = iface.tx_bytes.saturating_sub(ptx);
                let dx_rx_packets = iface.rx_packets.saturating_sub(prxp);
                let dx_tx_packets = iface.tx_packets.saturating_sub(ptxp);
                let dx_rx_errors = iface.rx_errors.saturating_sub(prxe);
                let dx_tx_errors = iface.tx_errors.saturating_sub(ptxe);
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
                    (
                        iface.rx_bytes,
                        iface.tx_bytes,
                        iface.rx_packets,
                        iface.tx_packets,
                        iface.rx_errors,
                        iface.tx_errors,
                    ),
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
        self.system_info.get_or_create(&info_labels).set(1);
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
        self.scrape_duration_seconds
            .get_or_create(labels)
            .set(millis);
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

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mikrotik::{InterfaceStats, SystemResource};

    fn make_router_metrics(
        router_name: &str,
        interfaces: Vec<InterfaceStats>,
        system: SystemResource,
    ) -> RouterMetrics {
        RouterMetrics {
            router_name: router_name.to_string(),
            interfaces,
            system,
        }
    }

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
            512 * 1024 * 1024 as i64
        );
        assert_eq!(
            registry
                .system_total_memory
                .get_or_create(&router_label)
                .get(),
            1024 * 1024 * 1024 as i64
        );
    }
}
