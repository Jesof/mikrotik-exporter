// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Shared fixtures for metric benchmarks.

use mikrotik_exporter::{
    CertificateStats, CollectionStatus, ConnectionTrackingStats, FirewallRuleStats, InterfaceStats,
    RouterMetrics, SystemResource, WireGuardPeerStats,
};

pub const INTERFACES_PER_ROUTER: usize = 64;
pub const CONNTRACK_SERIES_PER_ROUTER: usize = 1024;
pub const WIREGUARD_PEERS_PER_ROUTER: usize = 64;
pub const CERTIFICATES_PER_ROUTER: usize = 8;
pub const FIREWALL_RULES_PER_ROUTER: usize = 1024;

pub fn router_metrics(index: usize) -> RouterMetrics {
    let interfaces = (0..INTERFACES_PER_ROUTER)
        .map(|i| InterfaceStats {
            id: format!("iface-{index}-{i}"),
            name: format!("ether{i}"),
            comment: String::new(),
            rx_bytes: 1000 * (i as u64 + 1),
            tx_bytes: 2000 * (i as u64 + 1),
            rx_packets: 10 * (i as u64 + 1),
            tx_packets: 20 * (i as u64 + 1),
            rx_errors: Some(0),
            tx_errors: Some(0),
            running: i % 2 == 0,
        })
        .collect();

    let connection_tracking = (0..CONNTRACK_SERIES_PER_ROUTER)
        .map(|i| ConnectionTrackingStats {
            src_address: format!("10.{}.{}.{}", i / 65_536, (i / 256) % 256, i % 256),
            protocol: if i % 2 == 0 { "tcp" } else { "udp" }.to_string(),
            connection_count: (i as u64) % 100,
            ip_version: "ipv4".to_string(),
        })
        .collect();

    let wireguard_peers = (0..WIREGUARD_PEERS_PER_ROUTER)
        .map(|i| WireGuardPeerStats {
            id: format!("wg-{index}-{i}"),
            interface: "wg1".to_string(),
            name: format!("peer-{i}"),
            comment: String::new(),
            allowed_address: format!("10.9.{}.{}/32", i / 256, i % 256),
            endpoint: Some(format!("192.0.2.{i}:51820")),
            rx_bytes: 1000 * (i as u64 + 1),
            tx_bytes: 2000 * (i as u64 + 1),
            latest_handshake: Some(1_700_000_000 + i as u64),
        })
        .collect();

    let certificate_stats = (0..CERTIFICATES_PER_ROUTER)
        .map(|i| CertificateStats {
            id: format!("cert-{index}-{i}"),
            name: format!("cert-{i}"),
            days_until_expiry: (100 - i64::try_from(i).unwrap_or(100)) * 5,
        })
        .collect();

    let firewall_rules = (0..FIREWALL_RULES_PER_ROUTER)
        .map(|i| FirewallRuleStats {
            id: format!("rule-{index}-{i}"),
            comment: if i % 4 == 0 {
                "drop invalid".to_string()
            } else {
                String::new()
            },
            chain: if i % 3 == 0 {
                "forward".to_string()
            } else {
                "input".to_string()
            },
            action: if i % 2 == 0 {
                "accept".to_string()
            } else {
                "drop".to_string()
            },
            bytes: 1000 * (i as u64 + 1),
            packets: 10 * (i as u64 + 1),
            ip_version: if i % 5 == 0 {
                "ipv6".to_string()
            } else {
                "ipv4".to_string()
            },
            section: if i % 2 == 0 {
                "filter".to_string()
            } else {
                "mangle".to_string()
            },
        })
        .collect();

    RouterMetrics {
        router_name: format!("router-{index}"),
        collection_status: CollectionStatus::default(),
        interfaces,
        system: SystemResource {
            uptime: "1w2d3h4m5s".to_string(),
            cpu_load: 25,
            free_memory: 512 * 1024 * 1024,
            total_memory: 1024 * 1024 * 1024,
            version: "7.15".to_string(),
            board_name: "CCR2004".to_string(),
        },
        connection_tracking,
        wireguard_peers,
        certificate_stats,
        firewall_rules,
    }
}
