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
            let before_count = self.prev_iface.len();
            let stale: Vec<_> = self
                .prev_iface
                .iter()
                .filter(|entry| !current_interfaces.contains(entry.key()))
                .map(|entry| entry.key().clone())
                .collect();

            // Remove stale entries
            for label in &stale {
                self.prev_iface.remove(label);
            }

            let after_count = self.prev_iface.len();
            let removed = before_count.saturating_sub(after_count);
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
            let stale: Vec<_> = self
                .conntrack_last_seen
                .iter()
                .filter(|entry| now.duration_since(*entry.value()) > ttl)
                .map(|entry| entry.key().clone())
                .collect();

            // Remove stale entries
            for label in &stale {
                self.conntrack_last_seen.remove(label);
            }
            stale
        };
        if !stale_conntrack.is_empty() {
            // Clean up prev_conntrack entries for stale labels
            for label in &stale_conntrack {
                if let Some(mut set) = self.prev_conntrack.get_mut(&label.router) {
                    set.remove(label);
                    if set.is_empty() {
                        drop(set); // Release the mutable borrow
                        self.prev_conntrack.remove(&label.router);
                    }
                }
            }

            for label in &stale_conntrack {
                self.connection_tracking_count.remove(label);
            }
            tracing::debug!(
                "Expired {} conntrack labels via TTL cleanup",
                stale_conntrack.len()
            );
        }

        let stale_peers: Vec<WireGuardPeerLabels> = {
            let stale: Vec<_> = self
                .wireguard_peer_last_seen
                .iter()
                .filter(|entry| now.duration_since(*entry.value()) > ttl)
                .map(|entry| entry.key().clone())
                .collect();

            // Remove stale entries
            for label in &stale {
                self.wireguard_peer_last_seen.remove(label);
            }
            stale
        };
        if !stale_peers.is_empty() {
            // Clean up prev_wireguard_peers entries for stale labels
            for label in &stale_peers {
                if let Some(mut set) = self.prev_wireguard_peers.get_mut(&label.router) {
                    set.remove(label);
                    if set.is_empty() {
                        drop(set); // Release the mutable borrow
                        self.prev_wireguard_peers.remove(&label.router);
                    }
                }
            }

            for label in &stale_peers {
                self.wireguard_peer_rx_bytes.remove(label);
                self.wireguard_peer_tx_bytes.remove(label);
                self.wireguard_peer_latest_handshake.remove(label);
            }
            tracing::debug!(
                "Expired {} wireguard peer labels via TTL cleanup",
                stale_peers.len()
            );
        }

        let stale_peer_info: Vec<WireGuardPeerInfoLabels> = {
            let stale: Vec<_> = self
                .wireguard_peer_info_last_seen
                .iter()
                .filter(|entry| now.duration_since(*entry.value()) > ttl)
                .map(|entry| entry.key().clone())
                .collect();

            // Remove stale entries
            for label in &stale {
                self.wireguard_peer_info_last_seen.remove(label);
            }
            stale
        };
        if !stale_peer_info.is_empty() {
            // Clean up prev_wireguard_peer_info entries for stale labels
            // We need to iterate through all entries to find and remove the matching labels
            for label in &stale_peer_info {
                if let Some(mut map) = self.prev_wireguard_peer_info.get_mut(&label.router) {
                    let keys_to_remove: Vec<_> = map
                        .iter()
                        .filter(|(_, info)| *info == label)
                        .map(|(key, _)| key.clone())
                        .collect();

                    for key in keys_to_remove {
                        map.remove(&key);
                    }

                    if map.is_empty() {
                        drop(map); // Release the mutable borrow
                        self.prev_wireguard_peer_info.remove(&label.router);
                    }
                }
            }

            for label in &stale_peer_info {
                self.wireguard_peer_info.remove(label);
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
            let stale: Vec<_> = self
                .prev_iface
                .iter()
                .filter(|entry| !active_routers.contains(&entry.key().router))
                .map(|entry| entry.key().clone())
                .collect();

            // Remove stale entries
            for label in &stale {
                self.prev_iface.remove(label);
            }
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

        // Clean up system info for stale routers
        let stale_system: Vec<(String, SystemInfoLabels)> = {
            let mut stale = Vec::new();
            self.prev_system_info.retain(|router, labels| {
                if active_routers.contains(router) {
                    true
                } else {
                    stale_routers.insert(router.clone());
                    stale.push((router.clone(), labels.clone()));
                    false
                }
            });
            stale
        };
        for (_, label) in &stale_system {
            self.system_info.remove(label);
        }

        // Clean up conntrack for stale routers
        let stale_conntrack: Vec<ConntrackLabels> = {
            let mut stale = Vec::new();
            self.prev_conntrack.retain(|router, set| {
                if active_routers.contains(router) {
                    true
                } else {
                    stale_routers.insert(router.clone());
                    stale.extend(set.iter().cloned());
                    false
                }
            });
            stale
        };
        for label in &stale_conntrack {
            self.connection_tracking_count.remove(label);
        }

        // Clean up wireguard peers for stale routers
        let stale_peers: Vec<WireGuardPeerLabels> = {
            let mut stale = Vec::new();
            self.prev_wireguard_peers.retain(|router, set| {
                if active_routers.contains(router) {
                    true
                } else {
                    stale_routers.insert(router.clone());
                    stale.extend(set.iter().cloned());
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

        // Clean up wireguard peer info for stale routers
        let stale_peer_info: Vec<WireGuardPeerInfoLabels> = {
            let mut stale = Vec::new();
            self.prev_wireguard_peer_info.retain(|router, map| {
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

        // Clean up last seen maps
        let stale_conntrack_labels: Vec<_> = self
            .conntrack_last_seen
            .iter()
            .filter(|entry| !active_routers.contains(&entry.key().router))
            .map(|entry| entry.key().clone())
            .collect();
        for label in stale_conntrack_labels {
            self.conntrack_last_seen.remove(&label);
        }

        let stale_peer_labels: Vec<_> = self
            .wireguard_peer_last_seen
            .iter()
            .filter(|entry| !active_routers.contains(&entry.key().router))
            .map(|entry| entry.key().clone())
            .collect();
        for label in stale_peer_labels {
            self.wireguard_peer_last_seen.remove(&label);
        }

        let stale_peer_info_labels: Vec<_> = self
            .wireguard_peer_info_last_seen
            .iter()
            .filter(|entry| !active_routers.contains(&entry.key().router))
            .map(|entry| entry.key().clone())
            .collect();
        for label in stale_peer_info_labels {
            self.wireguard_peer_info_last_seen.remove(&label);
        }

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
