// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Cleanup helpers for stale and expired metric labels

use crate::metrics::labels::{
    CertificateLabels, ConntrackLabels, FirewallRuleInfoLabels, FirewallRuleLabels,
    InterfaceInfoLabels, InterfaceLabels, RouterLabels, WireGuardPeerInfoLabels,
    WireGuardPeerLabels,
};
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::Instant;

use super::MetricsRegistry;

impl MetricsRegistry {
    /// Clean up stale dynamic labels based on TTL to prevent unbounded growth
    pub fn cleanup_expired_dynamic_labels(&self, ttl: Duration) {
        let now = Instant::now();
        self.cleanup_expired_system_info(now, ttl);
        self.cleanup_expired_conntrack(now, ttl);
        self.cleanup_expired_wireguard_peers(now, ttl);
        self.cleanup_expired_certificates(now, ttl);
        self.cleanup_expired_firewall_rules(now, ttl);
        self.cleanup_expired_info_labels(now, ttl);
    }

    fn cleanup_expired_system_info(&self, now: Instant, ttl: Duration) {
        let stale_system_info: Vec<_> = self
            .system_info_last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();
        for labels in stale_system_info {
            self.system_info.remove(&labels);
            self.system_info_last_seen.remove(&labels);
            self.prev_system_info
                .remove_if(&labels.router, |_, current| current == &labels);
        }
    }

    fn cleanup_expired_conntrack(&self, now: Instant, ttl: Duration) {
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
            tracing::debug!(expired = count, "Expired conntrack labels via TTL cleanup");
            for entry in self.prev_conntrack.iter() {
                self.conntrack_active_series
                    .get_or_create(&RouterLabels {
                        router: entry.key().clone(),
                    })
                    .set(i64::try_from(entry.value().len()).unwrap_or(i64::MAX));
            }
        }
    }

    fn cleanup_expired_wireguard_peers(&self, now: Instant, ttl: Duration) {
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
                if let Some(mut map) = self.prev_wireguard_peer_info.get_mut(&label.router)
                    && let Some(info_label) = map.remove(label)
                {
                    self.wireguard_peer_info.remove(&info_label);
                    self.wireguard_peer_info_last_seen.remove(&info_label);
                }
            }
            tracing::debug!(
                expired = count,
                "Expired wireguard peer labels via TTL cleanup"
            );
        }
    }

    fn cleanup_expired_certificates(&self, now: Instant, ttl: Duration) {
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
            tracing::debug!(
                expired = count,
                "Expired certificate labels via TTL cleanup"
            );
        }
    }

    fn cleanup_expired_firewall_rules(&self, now: Instant, ttl: Duration) {
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
                if let Some(mut map) = self.prev_firewall_rule_info.get_mut(&label.router)
                    && let Some(info_label) = map.remove(label)
                {
                    self.firewall_rule_info.remove(&info_label);
                    self.firewall_rule_info_last_seen.remove(&info_label);
                }
            }
            tracing::debug!(
                expired = count,
                "Expired firewall rule labels via TTL cleanup"
            );
        }
    }

    /// Clean up expired info labels (metadata for entities that still exist).
    fn cleanup_expired_info_labels(&self, now: Instant, ttl: Duration) {
        // 1. Interface Info
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
            tracing::debug!(
                expired = count,
                "Expired interface info labels via TTL cleanup"
            );
        }

        // 2. WireGuard Peer Info
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
                expired = count,
                "Expired wireguard peer info labels via TTL cleanup"
            );
        }

        // 3. Firewall Rule Info
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
                expired = count,
                "Expired firewall rule info labels via TTL cleanup"
            );
        }
    }

    /// Clean up cached state for routers that are no longer configured
    pub fn cleanup_stale_routers(&self, active_routers: &HashSet<String>) {
        self.retain_active_last_seen(active_routers);

        let mut stale_routers: HashSet<_> = self
            .known_routers
            .iter()
            .filter(|entry| !active_routers.contains(entry.key()))
            .map(|entry| entry.key().clone())
            .collect();
        self.collect_stale_interfaces(active_routers, &mut stale_routers);
        self.collect_stale_system_info(active_routers, &mut stale_routers);
        self.collect_stale_conntrack(active_routers, &mut stale_routers);
        self.collect_stale_wireguard(active_routers);
        self.collect_stale_certificates(active_routers);
        self.collect_stale_firewall(active_routers);

        self.remove_stale_router_metrics(&stale_routers);
    }

    fn retain_active_last_seen(&self, active_routers: &HashSet<String>) {
        self.system_info_last_seen.retain(|labels, _| {
            if active_routers.contains(&labels.router) {
                true
            } else {
                self.system_info.remove(labels);
                false
            }
        });
        // Superseded metadata is no longer in the current per-router maps.
        self.interface_info_last_seen.retain(|labels, _| {
            if active_routers.contains(&labels.router) {
                true
            } else {
                self.interface_info.remove(labels);
                false
            }
        });
        self.wireguard_peer_info_last_seen.retain(|labels, _| {
            if active_routers.contains(&labels.router) {
                true
            } else {
                self.wireguard_peer_info.remove(labels);
                false
            }
        });
        self.firewall_rule_info_last_seen.retain(|labels, _| {
            if active_routers.contains(&labels.router) {
                true
            } else {
                self.firewall_rule_info.remove(labels);
                false
            }
        });
    }

    fn collect_stale_interfaces(
        &self,
        active_routers: &HashSet<String>,
        stale_routers: &mut HashSet<String>,
    ) {
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
    }

    fn collect_stale_system_info(
        &self,
        active_routers: &HashSet<String>,
        stale_routers: &mut HashSet<String>,
    ) {
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
    }

    fn collect_stale_conntrack(
        &self,
        active_routers: &HashSet<String>,
        stale_routers: &mut HashSet<String>,
    ) {
        // Conntrack
        self.prev_conntrack.retain(|router, set| {
            if active_routers.contains(router) {
                true
            } else {
                stale_routers.insert(router.clone());
                for label in set.iter() {
                    self.connection_tracking_count.remove(label);
                    self.conntrack_last_seen.remove(label);
                }
                false
            }
        });
    }

    fn collect_stale_wireguard(&self, active_routers: &HashSet<String>) {
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
    }

    fn collect_stale_certificates(&self, active_routers: &HashSet<String>) {
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
    }

    fn collect_stale_firewall(&self, active_routers: &HashSet<String>) {
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
    }

    fn remove_stale_router_metrics(&self, stale_routers: &HashSet<String>) {
        // General Router Metrics
        for router in stale_routers {
            let router_labels = RouterLabels {
                router: router.clone(),
            };
            self.system_cpu_load.remove(&router_labels);
            self.system_free_memory.remove(&router_labels);
            self.system_total_memory.remove(&router_labels);
            self.system_uptime_seconds.remove(&router_labels);
            self.scrape_success.remove(&router_labels);
            self.scrape_errors.remove(&router_labels);
            self.scrape_duration_seconds.remove(&router_labels);
            self.scrape_last_success_timestamp_seconds
                .remove(&router_labels);
            self.connection_consecutive_errors.remove(&router_labels);
            self.conntrack_active_series.remove(&router_labels);
            self.conntrack_update_duration_seconds
                .remove(&router_labels);
            self.conntrack_dropped_series.remove(&router_labels);
            for (group, _) in crate::mikrotik::CollectionStatus::default().group_states() {
                let labels = crate::metrics::labels::GroupLabels {
                    router: router.clone(),
                    group,
                };
                self.group_collection_success.remove(&labels);
                self.group_collection_complete.remove(&labels);
                self.group_last_success_timestamp_seconds.remove(&labels);
            }
            self.known_routers.remove(router);
            self.collected_routers.remove(router);
            self.last_scrape_success.remove(router);
            self.consecutive_scrape_errors.remove(router);
        }
    }
}
