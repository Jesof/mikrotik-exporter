// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Shared fixtures for `MetricsRegistry` unit tests.
//!
//! Kept in a dedicated `#[cfg(test)]` module so domain-specific tests can build
//! realistic `RouterMetrics` snapshots without duplicating construction logic.

use crate::metrics::RouterLabels;
use crate::mikrotik::{
    CollectionStatus, CollectionStatusParts, ConnectionTrackingStats, FetchState,
    FirewallRuleStats, InterfaceStats, RouterMetrics, SystemResource,
};

pub(crate) fn make_router_metrics(
    router_name: &str,
    interfaces: Vec<InterfaceStats>,
    system: SystemResource,
) -> RouterMetrics {
    RouterMetrics {
        router_name: router_name.to_string(),
        collection_status: CollectionStatus::default(),
        interfaces,
        system,
        connection_tracking: Vec::new(),
        wireguard_peers: Vec::new(),
        certificate_stats: Vec::new(),
        firewall_rules: vec![FirewallRuleStats {
            id: "*1".to_string(),
            comment: "Drop invalid".to_string(),
            chain: "forward".to_string(),
            action: "accept".to_string(),
            bytes: 1024,
            packets: 5,
            ip_version: "ipv4".to_string(),
            section: "filter".to_string(),
        }],
    }
}

pub(crate) fn make_conntrack(
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
pub(crate) fn make_interface(
    id: &str,
    name: &str,
    comment: &str,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_errors: u64,
    tx_errors: u64,
    running: bool,
) -> InterfaceStats {
    InterfaceStats {
        id: id.to_string(),
        name: name.to_string(),
        comment: comment.to_string(),
        rx_bytes,
        tx_bytes,
        rx_packets,
        tx_packets,
        rx_errors: Some(rx_errors),
        tx_errors: Some(tx_errors),
        running,
    }
}

pub(crate) fn make_system(version: &str, board_name: &str, uptime: &str) -> SystemResource {
    SystemResource {
        uptime: uptime.to_string(),
        cpu_load: 10,
        free_memory: 1024 * 1024 * 512,
        total_memory: 1024 * 1024 * 1024,
        version: version.to_string(),
        board_name: board_name.to_string(),
    }
}

pub(crate) fn make_partial_status(
    conntrack: FetchState,
    wireguard: FetchState,
    certificates: FetchState,
    firewall: FetchState,
) -> CollectionStatus {
    CollectionStatus::from_parts(CollectionStatusParts {
        system_interfaces: FetchState::Complete,
        conntrack,
        wireguard,
        certificates,
        firewall,
    })
}

pub(crate) fn make_firewall_rule(id: &str, bytes: u64, packets: u64) -> FirewallRuleStats {
    FirewallRuleStats {
        id: id.to_string(),
        comment: format!("rule-{id}"),
        chain: "forward".to_string(),
        action: "accept".to_string(),
        bytes,
        packets,
        ip_version: "ipv4".to_string(),
        section: "filter".to_string(),
    }
}

pub(crate) fn router_label(router: &str) -> RouterLabels {
    RouterLabels {
        router: router.to_string(),
    }
}

pub(crate) fn make_wireguard_peer(
    id: &str,
    rx_bytes: u64,
    tx_bytes: u64,
    latest_handshake: Option<u64>,
) -> crate::mikrotik::WireGuardPeerStats {
    crate::mikrotik::WireGuardPeerStats {
        id: id.to_string(),
        interface: "wg1".to_string(),
        name: "peer1".to_string(),
        comment: String::new(),
        allowed_address: "10.0.0.2/32".to_string(),
        endpoint: Some("1.1.1.1:51820".to_string()),
        rx_bytes,
        tx_bytes,
        latest_handshake,
    }
}
