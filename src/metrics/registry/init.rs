// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Registry initialization and metric registration

use crate::metrics::labels::{
    ConntrackLabels, InterfaceLabels, RouterLabels, SystemInfoLabels, WireGuardPeerInfoLabels,
    WireGuardPeerLabels,
};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::MetricsRegistry;

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

        let wireguard_peer_info = Family::<WireGuardPeerInfoLabels, Gauge>::default();
        registry.register(
            "mikrotik_wireguard_peer_info",
            "Static WireGuard peer info (value=1)",
            wireguard_peer_info.clone(),
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
            wireguard_peer_info,
            prev_iface: Arc::new(Mutex::new(HashMap::new())),
            prev_conntrack: Arc::new(Mutex::new(HashMap::new())),
            prev_system_info: Arc::new(Mutex::new(HashMap::new())),
            prev_wireguard_peers: Arc::new(Mutex::new(HashMap::new())),
            prev_wireguard_peer_info: Arc::new(Mutex::new(HashMap::new())),
            conntrack_last_seen: Arc::new(Mutex::new(HashMap::new())),
            wireguard_peer_last_seen: Arc::new(Mutex::new(HashMap::new())),
            wireguard_peer_info_last_seen: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
