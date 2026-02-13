// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Cleanup helpers for stale and expired metric labels

use crate::metrics::labels::{
    ConntrackLabels, InterfaceLabels, RouterLabels, SystemInfoLabels, WireGuardPeerInfoLabels,
    WireGuardPeerLabels,
};
use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::MetricsRegistry;

impl MetricsRegistry {
    /// Clean up stale interface metrics for interfaces that no longer exist
    ///
    /// This method removes old interface snapshots and label sets to prevent
    /// unbounded memory growth when interfaces are dynamically added/removed.
    ///
    /// # Arguments
    /// * `current_interfaces` - Set of currently active interface labels
    pub(crate) async fn cleanup_stale_interfaces(
        &self,
        current_interfaces: &HashSet<InterfaceLabels>,
    ) {
        let stale_interfaces: Vec<InterfaceLabels> = {
            let mut prev = self.prev_iface.lock().await;
            let before_count = prev.len();
            let stale: Vec<_> = prev
                .keys()
                .filter(|labels| !current_interfaces.contains(*labels))
                .cloned()
                .collect();
            prev.retain(|labels, _| current_interfaces.contains(labels));
            let after_count = prev.len();
            let removed = before_count - after_count;
            if removed > 0 {
                tracing::debug!("Cleaned up {} stale interface snapshots", removed);
            }
            stale
        };

        if !stale_interfaces.is_empty() {
            for labels in &stale_interfaces {
                self.interface_rx_bytes.remove(labels);
                self.interface_tx_bytes.remove(labels);
                self.interface_rx_packets.remove(labels);
                self.interface_tx_packets.remove(labels);
                self.interface_rx_errors.remove(labels);
                self.interface_tx_errors.remove(labels);
                self.interface_running.remove(labels);
            }
            tracing::debug!(
                "Removed {} stale interface label sets",
                stale_interfaces.len()
            );
        }
    }

    /// Clean up stale dynamic labels based on TTL to prevent unbounded growth
    pub async fn cleanup_expired_dynamic_labels(&self, ttl: Duration) {
        let now = Instant::now();

        let stale_conntrack: Vec<ConntrackLabels> = {
            let mut last_seen = self.conntrack_last_seen.lock().await;
            let stale: Vec<_> = last_seen
                .iter()
                .filter(|(_, ts)| now.duration_since(**ts) > ttl)
                .map(|(label, _)| label.clone())
                .collect();
            for label in &stale {
                last_seen.remove(label);
            }
            stale
        };
        if !stale_conntrack.is_empty() {
            let mut prev_map = self.prev_conntrack.lock().await;
            for label in &stale_conntrack {
                self.connection_tracking_count.remove(label);
                if let Some(set) = prev_map.get_mut(&label.router) {
                    set.remove(label);
                    if set.is_empty() {
                        prev_map.remove(&label.router);
                    }
                }
            }
            tracing::debug!(
                "Expired {} conntrack labels via TTL cleanup",
                stale_conntrack.len()
            );
        }

        let stale_peers: Vec<WireGuardPeerLabels> = {
            let mut last_seen = self.wireguard_peer_last_seen.lock().await;
            let stale: Vec<_> = last_seen
                .iter()
                .filter(|(_, ts)| now.duration_since(**ts) > ttl)
                .map(|(label, _)| label.clone())
                .collect();
            for label in &stale {
                last_seen.remove(label);
            }
            stale
        };
        if !stale_peers.is_empty() {
            let mut prev_map = self.prev_wireguard_peers.lock().await;
            for label in &stale_peers {
                self.wireguard_peer_rx_bytes.remove(label);
                self.wireguard_peer_tx_bytes.remove(label);
                self.wireguard_peer_latest_handshake.remove(label);
                if let Some(set) = prev_map.get_mut(&label.router) {
                    set.remove(label);
                    if set.is_empty() {
                        prev_map.remove(&label.router);
                    }
                }
            }
            tracing::debug!(
                "Expired {} wireguard peer labels via TTL cleanup",
                stale_peers.len()
            );
        }

        let stale_peer_info: Vec<WireGuardPeerInfoLabels> = {
            let mut last_seen = self.wireguard_peer_info_last_seen.lock().await;
            let stale: Vec<_> = last_seen
                .iter()
                .filter(|(_, ts)| now.duration_since(**ts) > ttl)
                .map(|(label, _)| label.clone())
                .collect();
            for label in &stale {
                last_seen.remove(label);
            }
            stale
        };
        if !stale_peer_info.is_empty() {
            let mut prev_map = self.prev_wireguard_peer_info.lock().await;
            for label in &stale_peer_info {
                self.wireguard_peer_info.remove(label);
                if let Some(map) = prev_map.get_mut(&label.router) {
                    map.retain(|_, info| info != label);
                    if map.is_empty() {
                        prev_map.remove(&label.router);
                    }
                }
            }
            tracing::debug!(
                "Expired {} wireguard peer info labels via TTL cleanup",
                stale_peer_info.len()
            );
        }
    }

    /// Clean up cached state for routers that are no longer configured
    pub async fn cleanup_stale_routers(&self, active_routers: &HashSet<String>) {
        let mut stale_routers = HashSet::new();

        let stale_interfaces: Vec<InterfaceLabels> = {
            let mut prev_iface = self.prev_iface.lock().await;
            let stale: Vec<_> = prev_iface
                .keys()
                .filter(|labels| !active_routers.contains(&labels.router))
                .cloned()
                .collect();
            prev_iface.retain(|labels, _| active_routers.contains(&labels.router));
            stale
        };
        for label in &stale_interfaces {
            stale_routers.insert(label.router.clone());
            self.interface_rx_bytes.remove(label);
            self.interface_tx_bytes.remove(label);
            self.interface_rx_packets.remove(label);
            self.interface_tx_packets.remove(label);
            self.interface_rx_errors.remove(label);
            self.interface_tx_errors.remove(label);
            self.interface_running.remove(label);
        }

        let stale_system: Vec<SystemInfoLabels> = {
            let mut prev_system = self.prev_system_info.lock().await;
            let mut stale = Vec::new();
            prev_system.retain(|router, labels| {
                if active_routers.contains(router) {
                    true
                } else {
                    stale_routers.insert(router.clone());
                    stale.push(labels.clone());
                    false
                }
            });
            stale
        };
        for label in &stale_system {
            self.system_info.remove(label);
        }

        let stale_conntrack: Vec<ConntrackLabels> = {
            let mut prev_map = self.prev_conntrack.lock().await;
            let mut stale = Vec::new();
            prev_map.retain(|router, labels| {
                if active_routers.contains(router) {
                    true
                } else {
                    stale_routers.insert(router.clone());
                    stale.extend(labels.iter().cloned());
                    false
                }
            });
            stale
        };
        for label in &stale_conntrack {
            self.connection_tracking_count.remove(label);
        }

        let stale_peers: Vec<WireGuardPeerLabels> = {
            let mut prev_map = self.prev_wireguard_peers.lock().await;
            let mut stale = Vec::new();
            prev_map.retain(|router, labels| {
                if active_routers.contains(router) {
                    true
                } else {
                    stale_routers.insert(router.clone());
                    stale.extend(labels.iter().cloned());
                    false
                }
            });
            stale
        };
        for label in &stale_peers {
            self.wireguard_peer_rx_bytes.remove(label);
            self.wireguard_peer_tx_bytes.remove(label);
            self.wireguard_peer_latest_handshake.remove(label);
        }

        let stale_peer_info: Vec<WireGuardPeerInfoLabels> = {
            let mut prev_map = self.prev_wireguard_peer_info.lock().await;
            let mut stale = Vec::new();
            prev_map.retain(|router, map| {
                if active_routers.contains(router) {
                    true
                } else {
                    stale_routers.insert(router.clone());
                    stale.extend(map.values().cloned());
                    false
                }
            });
            stale
        };
        for label in &stale_peer_info {
            self.wireguard_peer_info.remove(label);
        }

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
        }

        let mut conntrack_seen = self.conntrack_last_seen.lock().await;
        conntrack_seen.retain(|label, _| active_routers.contains(&label.router));

        let mut peer_seen = self.wireguard_peer_last_seen.lock().await;
        peer_seen.retain(|label, _| active_routers.contains(&label.router));

        let mut peer_info_seen = self.wireguard_peer_info_last_seen.lock().await;
        peer_info_seen.retain(|label, _| active_routers.contains(&label.router));

        if !stale_interfaces.is_empty()
            || !stale_system.is_empty()
            || !stale_conntrack.is_empty()
            || !stale_peers.is_empty()
            || !stale_peer_info.is_empty()
        {
            tracing::debug!(
                "Removed stale router data: interfaces={}, system_info={}, conntrack={}, wg_peers={}, wg_peer_info={}",
                stale_interfaces.len(),
                stale_system.len(),
                stale_conntrack.len(),
                stale_peers.len(),
                stale_peer_info.len()
            );
        }
    }
}
