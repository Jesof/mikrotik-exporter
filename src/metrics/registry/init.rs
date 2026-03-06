// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Registry initialization and metric registration

use crate::metrics::labels::{
    CertificateLabels, ConntrackLabels, FirewallRuleInfoLabels, FirewallRuleLabels,
    InterfaceInfoLabels, InterfaceLabels, RouterLabels, SystemInfoLabels, WireGuardPeerInfoLabels,
    WireGuardPeerLabels,
};
use dashmap::DashMap;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::MetricsRegistry;

type InterfaceMetrics = (
    Family<InterfaceLabels, Counter>,
    Family<InterfaceLabels, Counter>,
    Family<InterfaceLabels, Counter>,
    Family<InterfaceLabels, Counter>,
    Family<InterfaceLabels, Counter>,
    Family<InterfaceLabels, Counter>,
    Family<InterfaceLabels, Gauge>,
    Family<InterfaceInfoLabels, Gauge>,
);

type FirewallMetrics = (
    Family<FirewallRuleLabels, Counter>,
    Family<FirewallRuleLabels, Counter>,
    Family<FirewallRuleInfoLabels, Gauge>,
);

type SystemMetrics = (
    Family<RouterLabels, Gauge>,
    Family<RouterLabels, Gauge>,
    Family<RouterLabels, Gauge>,
    Family<SystemInfoLabels, Gauge>,
    Family<RouterLabels, Gauge>,
);

type ScrapeMetrics = (
    Family<RouterLabels, Counter>,
    Family<RouterLabels, Counter>,
    Family<RouterLabels, Gauge>,
    Family<RouterLabels, Gauge>,
    Family<RouterLabels, Gauge>,
);

type ConntrackMetrics = (
    Family<ConntrackLabels, Gauge>,
    Family<RouterLabels, Gauge>,
    Family<RouterLabels, Gauge>,
);

type WireGuardMetrics = (
    Family<WireGuardPeerLabels, Gauge>,
    Family<WireGuardPeerLabels, Gauge>,
    Family<WireGuardPeerLabels, Gauge>,
    Family<WireGuardPeerInfoLabels, Gauge>,
);

impl MetricsRegistry {
    #[allow(clippy::similar_names)]
    fn register_firewall_metrics(registry: &mut Registry) -> FirewallMetrics {
        let firewall_rule_bytes = Family::<FirewallRuleLabels, Counter>::default();
        registry.register(
            "mikrotik_firewall_rule_bytes",
            "Bytes matched by firewall rule",
            firewall_rule_bytes.clone(),
        );
        let firewall_rule_packets = Family::<FirewallRuleLabels, Counter>::default();
        registry.register(
            "mikrotik_firewall_rule_packets",
            "Packets matched by firewall rule",
            firewall_rule_packets.clone(),
        );

        let firewall_rule_info = Family::<FirewallRuleInfoLabels, Gauge>::default();
        registry.register(
            "mikrotik_firewall_rule_info",
            "Static firewall rule info (value=1)",
            firewall_rule_info.clone(),
        );

        (
            firewall_rule_bytes,
            firewall_rule_packets,
            firewall_rule_info,
        )
    }

    #[allow(clippy::similar_names)]
    fn register_interface_metrics(registry: &mut Registry) -> InterfaceMetrics {
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

        let interface_info = Family::<InterfaceInfoLabels, Gauge>::default();
        registry.register(
            "mikrotik_interface_info",
            "Static interface info (value=1)",
            interface_info.clone(),
        );

        (
            interface_rx_bytes,
            interface_tx_bytes,
            interface_rx_packets,
            interface_tx_packets,
            interface_rx_errors,
            interface_tx_errors,
            interface_running,
            interface_info,
        )
    }

    fn register_system_metrics(registry: &mut Registry) -> SystemMetrics {
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

        (
            system_cpu_load,
            system_free_memory,
            system_total_memory,
            system_info,
            system_uptime_seconds,
        )
    }

    fn register_scrape_metrics(registry: &mut Registry) -> ScrapeMetrics {
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

        (
            scrape_success,
            scrape_errors,
            scrape_duration_milliseconds,
            scrape_last_success_timestamp_seconds,
            connection_consecutive_errors,
        )
    }

    fn register_collection_metrics(registry: &mut Registry) -> Gauge {
        let collection_cycle_duration_milliseconds = Gauge::default();
        registry.register(
            "mikrotik_collection_cycle_duration_milliseconds",
            "Duration of full collection cycle in milliseconds",
            collection_cycle_duration_milliseconds.clone(),
        );
        collection_cycle_duration_milliseconds
    }

    fn register_pool_metrics(registry: &mut Registry) -> (Gauge, Gauge) {
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
        (connection_pool_size, connection_pool_active)
    }

    fn register_conntrack_metrics(registry: &mut Registry) -> ConntrackMetrics {
        let connection_tracking_count = Family::<ConntrackLabels, Gauge>::default();
        registry.register(
            "mikrotik_connection_tracking_count",
            "Number of tracked connections per source address and protocol",
            connection_tracking_count.clone(),
        );
        let conntrack_active_series = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_conntrack_active_series",
            "Number of active conntrack label series per router",
            conntrack_active_series.clone(),
        );
        let conntrack_update_duration_milliseconds = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_conntrack_update_duration_milliseconds",
            "Duration of conntrack metrics update in milliseconds",
            conntrack_update_duration_milliseconds.clone(),
        );

        (
            connection_tracking_count,
            conntrack_active_series,
            conntrack_update_duration_milliseconds,
        )
    }

    #[allow(clippy::similar_names)]
    fn register_wireguard_metrics(registry: &mut Registry) -> WireGuardMetrics {
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

        let wireguard_peer_info = Family::<WireGuardPeerInfoLabels, Gauge>::default();
        registry.register(
            "mikrotik_wireguard_peer_info",
            "Static WireGuard peer info (value=1)",
            wireguard_peer_info.clone(),
        );

        (
            wireguard_peer_rx_bytes,
            wireguard_peer_tx_bytes,
            wireguard_peer_latest_handshake,
            wireguard_peer_info,
        )
    }

    fn register_certificate_metrics(registry: &mut Registry) -> Family<CertificateLabels, Gauge> {
        let certificate_days_until_expiry = Family::<CertificateLabels, Gauge>::default();
        registry.register(
            "mikrotik_certificate_days_until_expiry",
            "Days until certificate expiry",
            certificate_days_until_expiry.clone(),
        );
        certificate_days_until_expiry
    }
    #[allow(clippy::similar_names)]
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Registry::default();

        // Register interface metrics
        let (
            interface_rx_bytes,
            interface_tx_bytes,
            interface_rx_packets,
            interface_tx_packets,
            interface_rx_errors,
            interface_tx_errors,
            interface_running,
            interface_info,
        ) = Self::register_interface_metrics(&mut registry);

        // Register firewall metrics
        let (firewall_rule_bytes, firewall_rule_packets, firewall_rule_info) =
            Self::register_firewall_metrics(&mut registry);

        // Register system metrics
        let (
            system_cpu_load,
            system_free_memory,
            system_total_memory,
            system_info,
            system_uptime_seconds,
        ) = Self::register_system_metrics(&mut registry);

        // Register scrape metrics
        let (
            scrape_success,
            scrape_errors,
            scrape_duration_milliseconds,
            scrape_last_success_timestamp_seconds,
            connection_consecutive_errors,
        ) = Self::register_scrape_metrics(&mut registry);

        // Register collection metrics
        let collection_cycle_duration_milliseconds =
            Self::register_collection_metrics(&mut registry);

        // Register connection pool metrics
        let (connection_pool_size, connection_pool_active) =
            Self::register_pool_metrics(&mut registry);

        // Register connection tracking metrics
        let (
            connection_tracking_count,
            conntrack_active_series,
            conntrack_update_duration_milliseconds,
        ) = Self::register_conntrack_metrics(&mut registry);

        // Register WireGuard metrics
        let (
            wireguard_peer_rx_bytes,
            wireguard_peer_tx_bytes,
            wireguard_peer_latest_handshake,
            wireguard_peer_info,
        ) = Self::register_wireguard_metrics(&mut registry);

        // Register certificate metrics
        let certificate_days_until_expiry = Self::register_certificate_metrics(&mut registry);

        Self {
            registry: Arc::new(Mutex::new(registry)),
            interface_rx_bytes,
            interface_tx_bytes,
            interface_rx_packets,
            interface_tx_packets,
            interface_rx_errors,
            interface_tx_errors,
            firewall_rule_bytes,
            firewall_rule_packets,
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
            conntrack_active_series,
            conntrack_update_duration_milliseconds,
            wireguard_peer_rx_bytes,
            wireguard_peer_tx_bytes,
            wireguard_peer_latest_handshake,
            wireguard_peer_info,
            certificate_days_until_expiry,
            interface_info,
            firewall_rule_info,
            prev_iface: Arc::new(DashMap::new()),
            prev_firewall_rules: Arc::new(DashMap::new()),
            prev_conntrack: Arc::new(DashMap::new()),
            prev_system_info: Arc::new(DashMap::new()),
            prev_wireguard_peers: Arc::new(DashMap::new()),
            prev_wireguard_peer_info: Arc::new(DashMap::new()),
            prev_interface_info: Arc::new(DashMap::new()),
            prev_firewall_rule_info: Arc::new(DashMap::new()),
            prev_certificates: Arc::new(DashMap::new()),
            prev_firewall_rules_by_router: Arc::new(DashMap::new()),
            conntrack_last_seen: Arc::new(DashMap::new()),
            firewall_rule_last_seen: Arc::new(DashMap::new()),
            firewall_rule_info_last_seen: Arc::new(DashMap::new()),
            wireguard_peer_last_seen: Arc::new(DashMap::new()),
            wireguard_peer_info_last_seen: Arc::new(DashMap::new()),
            certificate_last_seen: Arc::new(DashMap::new()),
            interface_info_last_seen: Arc::new(DashMap::new()),
            last_scrape_success: Arc::new(DashMap::new()),
            consecutive_scrape_errors: Arc::new(DashMap::new()),
        }
    }
}
