// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Cleanup helpers for stale and expired metric labels

use crate::metrics::labels::{
    CertificateLabels, ConntrackLabels, FirewallRuleInfoLabels, FirewallRuleLabels,
    InterfaceInfoLabels, InterfaceLabels, RouterLabels, WireGuardPeerInfoLabels,
    WireGuardPeerLabels,
};
use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::MetricsRegistry;

impl MetricsRegistry {
    /// Clean up stale dynamic labels based on TTL to prevent unbounded growth
    #[allow(clippy::unused_async)]
    pub async fn cleanup_expired_dynamic_labels(&self, ttl: Duration) {
        let now = Instant::now();

        // 1. Conntrack
        let stale_conntrack: Vec<ConntrackLabels> = {
            let stale: Vec<_> = self
                .conntrack_last_seen
                .iter()
                .filter(|entry| now.duration_since(*entry.value()) > ttl)
                .map(|entry| entry.key().clone())
                .collect();

            for label in &stale {
                self.conntrack_last_seen.remove(label);
            }
            stale
        };
        if !stale_conntrack.is_empty() {
            let count = stale_conntrack.len();
            for label in &stale_conntrack {
                if let Some(mut set) = self.prev_conntrack.get_mut(&label.router) {
                    set.remove(label);
                }
                self.connection_tracking_count.remove(label);
            }
            tracing::debug!("Expired {} conntrack labels via TTL cleanup", count);
        }

        // 2. WireGuard Peers
        let stale_peers: Vec<WireGuardPeerLabels> = {
            let stale: Vec<_> = self
                .wireguard_peer_last_seen
                .iter()
                .filter(|entry| now.duration_since(*entry.value()) > ttl)
                .map(|entry| entry.key().clone())
                .collect();

            for label in &stale {
                self.wireguard_peer_last_seen.remove(label);
            }
            stale
        };
        if !stale_peers.is_empty() {
            let count = stale_peers.len();
            for label in &stale_peers {
                if let Some(mut set) = self.prev_wireguard_peers.get_mut(&label.router) {
                    set.remove(label);
                }
                self.wireguard_peer_rx_bytes.remove(label);
                self.wireguard_peer_tx_bytes.remove(label);
                self.wireguard_peer_latest_handshake.remove(label);

                // Clean up info
                if let Some(mut map) = self.prev_wireguard_peer_info.get_mut(&label.router) {
                    if let Some(info_label) = map.remove(label) {
                        self.wireguard_peer_info.remove(&info_label);
                        self.wireguard_peer_info_last_seen.remove(&info_label);
                    }
                }
            }
            tracing::debug!("Expired {} wireguard peer labels via TTL cleanup", count);
        }

        // 3. Certificates
        let stale_certificates: Vec<CertificateLabels> = {
            let stale: Vec<_> = self
                .certificate_last_seen
                .iter()
                .filter(|entry| now.duration_since(*entry.value()) > ttl)
                .map(|entry| entry.key().clone())
                .collect();

            for label in &stale {
                self.certificate_last_seen.remove(label);
            }
            stale
        };
        if !stale_certificates.is_empty() {
            let count = stale_certificates.len();
            for label in &stale_certificates {
                if let Some(mut set) = self.prev_certificates.get_mut(&label.router) {
                    set.remove(label);
                }
                self.certificate_days_until_expiry.remove(label);
            }
            tracing::debug!("Expired {} certificate labels via TTL cleanup", count);
        }

        // 4. Firewall Rules
        let stale_firewall_rules: Vec<FirewallRuleLabels> = {
            let stale: Vec<_> = self
                .firewall_rule_last_seen
                .iter()
                .filter(|entry| now.duration_since(*entry.value()) > ttl)
                .map(|entry| entry.key().clone())
                .collect();

            for label in &stale {
                self.firewall_rule_last_seen.remove(label);
            }
            stale
        };
        if !stale_firewall_rules.is_empty() {
            let count = stale_firewall_rules.len();
            for label in &stale_firewall_rules {
                if let Some(mut set) = self.prev_firewall_rules_by_router.get_mut(&label.router) {
                    set.remove(label);
                }
                self.prev_firewall_rules.remove(label);
                self.firewall_rule_bytes.remove(label);
                self.firewall_rule_packets.remove(label);

                // Clean up info
                if let Some(mut map) = self.prev_firewall_rule_info.get_mut(&label.router) {
                    if let Some(info_label) = map.remove(label) {
                        self.firewall_rule_info.remove(&info_label);
                        self.firewall_rule_info_last_seen.remove(&info_label);
                    }
                }
            }
            tracing::debug!("Expired {} firewall rule labels via TTL cleanup", count);
        }

        // 5. Info Labels TTL (handles metadata changes when entity still exists)

        // 5.1 Interface Info
        let stale_iface_info: Vec<InterfaceInfoLabels> = self
            .interface_info_last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();
        if !stale_iface_info.is_empty() {
            let count = stale_iface_info.len();
            for label in stale_iface_info {
                self.interface_info_last_seen.remove(&label);
                self.interface_info.remove(&label);
            }
            tracing::debug!("Expired {} interface info labels via TTL cleanup", count);
        }

        // 5.2 WireGuard Peer Info
        let stale_peer_info: Vec<WireGuardPeerInfoLabels> = self
            .wireguard_peer_info_last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();
        if !stale_peer_info.is_empty() {
            let count = stale_peer_info.len();
            for label in stale_peer_info {
                self.wireguard_peer_info_last_seen.remove(&label);
                self.wireguard_peer_info.remove(&label);
            }
            tracing::debug!(
                "Expired {} wireguard peer info labels via TTL cleanup",
                count
            );
        }

        // 5.4 Firewall Rule Info
        let stale_rule_info: Vec<FirewallRuleInfoLabels> = self
            .firewall_rule_info_last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();
        if !stale_rule_info.is_empty() {
            let count = stale_rule_info.len();
            for label in stale_rule_info {
                self.firewall_rule_info_last_seen.remove(&label);
                self.firewall_rule_info.remove(&label);
            }
            tracing::debug!(
                "Expired {} firewall rule info labels via TTL cleanup",
                count
            );
        }
    }

    /// Clean up cached state for routers that are no longer configured
    #[allow(clippy::unused_async)]
    pub async fn cleanup_stale_routers(&self, active_routers: &HashSet<String>) {
        let mut stale_routers = HashSet::new();

        // Interfaces
        let stale_interfaces: Vec<InterfaceLabels> = self
            .prev_iface
            .iter()
            .filter(|entry| !active_routers.contains(&entry.key().router))
            .map(|entry| entry.key().clone())
            .collect();
        for label in stale_interfaces {
            stale_routers.insert(label.router.clone());
            self.prev_iface.remove(&label);
            self.interface_rx_bytes.remove(&label);
            self.interface_tx_bytes.remove(&label);
            self.interface_rx_packets.remove(&label);
            self.interface_tx_packets.remove(&label);
            self.interface_rx_errors.remove(&label);
            self.interface_tx_errors.remove(&label);
            self.interface_running.remove(&label);
        }
        self.prev_interface_info.retain(|router, map| {
            if active_routers.contains(router) {
                true
            } else {
                for info_label in map.values() {
                    self.interface_info.remove(info_label);
                    self.interface_info_last_seen.remove(info_label);
                }
                false
            }
        });

        // System Info
        self.prev_system_info.retain(|router, label| {
            if active_routers.contains(router) {
                true
            } else {
                stale_routers.insert(router.clone());
                self.system_info.remove(label);
                false
            }
        });

        // Conntrack
        self.prev_conntrack.retain(|router, set| {
            if active_routers.contains(router) {
                true
            } else {
                for label in set.iter() {
                    self.connection_tracking_count.remove(label);
                    self.conntrack_last_seen.remove(label);
                }
                false
            }
        });

        // WireGuard
        self.prev_wireguard_peers.retain(|router, set| {
            if active_routers.contains(router) {
                true
            } else {
                for label in set.iter() {
                    self.wireguard_peer_rx_bytes.remove(label);
                    self.wireguard_peer_tx_bytes.remove(label);
                    self.wireguard_peer_latest_handshake.remove(label);
                    self.wireguard_peer_last_seen.remove(label);
                }
                false
            }
        });
        self.prev_wireguard_peer_info.retain(|router, map| {
            if active_routers.contains(router) {
                true
            } else {
                for info_label in map.values() {
                    self.wireguard_peer_info.remove(info_label);
                    self.wireguard_peer_info_last_seen.remove(info_label);
                }
                false
            }
        });

        // Certificates
        self.prev_certificates.retain(|router, set| {
            if active_routers.contains(router) {
                true
            } else {
                for label in set.iter() {
                    self.certificate_days_until_expiry.remove(label);
                    self.certificate_last_seen.remove(label);
                }
                false
            }
        });

        // Firewall
        self.prev_firewall_rules_by_router.retain(|router, set| {
            if active_routers.contains(router) {
                true
            } else {
                for label in set.iter() {
                    self.prev_firewall_rules.remove(label);
                    self.firewall_rule_bytes.remove(label);
                    self.firewall_rule_packets.remove(label);
                    self.firewall_rule_last_seen.remove(label);
                }
                false
            }
        });
        self.prev_firewall_rule_info.retain(|router, map| {
            if active_routers.contains(router) {
                true
            } else {
                for info_label in map.values() {
                    self.firewall_rule_info.remove(info_label);
                    self.firewall_rule_info_last_seen.remove(info_label);
                }
                false
            }
        });

        // General Router Metrics
        for router in &stale_routers {
            let router_labels = RouterLabels {
                router: router.clone(),
            };
            self.system_cpu_load.remove(&router_labels);
            self.system_free_memory.remove(&router_labels);
            self.system_total_memory.remove(&router_labels);
            self.system_uptime_seconds.remove(&router_labels);
            self.scrape_success.remove(&router_labels);
            self.scrape_errors.remove(&router_labels);
            self.scrape_duration_milliseconds.remove(&router_labels);
            self.scrape_last_success_timestamp_seconds
                .remove(&router_labels);
            self.connection_consecutive_errors.remove(&router_labels);
            self.last_scrape_success.remove(router);
        }
    }
}
