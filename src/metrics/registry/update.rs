// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Metric update logic for router snapshots

use crate::metrics::labels::{
    ConntrackLabels, InterfaceLabels, RouterLabels, SystemInfoLabels, WireGuardInterfaceLabels,
    WireGuardPeerInfoLabels, WireGuardPeerLabels,
};
use crate::metrics::parsers::parse_uptime_to_seconds;
use crate::mikrotik::{RouterMetrics, WireGuardPeerStats};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use super::{InterfaceSnapshot, MetricsRegistry};

impl MetricsRegistry {
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
        let now = Instant::now();
        let mut current_conntrack = HashSet::new();
        let mut conntrack_seen = self.conntrack_last_seen.lock().await;
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
            conntrack_seen.insert(ct_labels, now);
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
        let mut deduped_peers = HashMap::new();
        let should_replace = |existing: &WireGuardPeerStats, candidate: &WireGuardPeerStats| match (
            candidate.latest_handshake,
            existing.latest_handshake,
        ) {
            (Some(candidate_ts), Some(existing_ts)) => {
                if candidate_ts != existing_ts {
                    candidate_ts > existing_ts
                } else {
                    candidate.rx_bytes.saturating_add(candidate.tx_bytes)
                        > existing.rx_bytes.saturating_add(existing.tx_bytes)
                }
            }
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => {
                candidate.rx_bytes.saturating_add(candidate.tx_bytes)
                    > existing.rx_bytes.saturating_add(existing.tx_bytes)
            }
        };
        for wg_peer in &metrics.wireguard_peers {
            let wg_peer_labels = WireGuardPeerLabels {
                router: metrics.router_name.clone(),
                interface: wg_peer.interface.clone(),
                allowed_address: wg_peer.allowed_address.clone(),
            };
            if let Some(existing) = deduped_peers.get(&wg_peer_labels) {
                if should_replace(existing, wg_peer) {
                    deduped_peers.insert(wg_peer_labels, wg_peer.clone());
                }
            } else {
                deduped_peers.insert(wg_peer_labels, wg_peer.clone());
            }
        }

        let mut current_peers = HashSet::new();
        let mut current_peer_info = HashMap::new();
        let mut peer_seen = self.wireguard_peer_last_seen.lock().await;
        let mut peer_info_seen = self.wireguard_peer_info_last_seen.lock().await;
        for (wg_peer_labels, wg_peer) in deduped_peers {
            current_peers.insert(wg_peer_labels.clone());
            let endpoint = wg_peer
                .endpoint
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let info_labels = WireGuardPeerInfoLabels {
                router: wg_peer_labels.router.clone(),
                interface: wg_peer_labels.interface.clone(),
                allowed_address: wg_peer_labels.allowed_address.clone(),
                name: wg_peer.name.clone(),
                endpoint,
            };
            current_peer_info.insert(wg_peer_labels.clone(), info_labels.clone());
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
                } else {
                    self.wireguard_peer_latest_handshake
                        .get_or_create(&wg_peer_labels)
                        .set(0);
                }
                self.wireguard_peer_info.get_or_create(&info_labels).set(1);
            }
            peer_seen.insert(wg_peer_labels, now);
            peer_info_seen.insert(info_labels, now);
        }

        {
            let mut prev_peers = self.prev_wireguard_peers.lock().await;
            let prev_labels = prev_peers
                .entry(metrics.router_name.clone())
                .or_insert_with(HashSet::new);
            for stale in prev_labels.difference(&current_peers) {
                #[allow(clippy::cast_possible_wrap)]
                {
                    self.wireguard_peer_rx_bytes.get_or_create(stale).set(0);
                    self.wireguard_peer_tx_bytes.get_or_create(stale).set(0);
                    self.wireguard_peer_latest_handshake
                        .get_or_create(stale)
                        .set(0);
                }
            }
            *prev_labels = current_peers;
        }

        {
            let mut prev_info = self.prev_wireguard_peer_info.lock().await;
            let prev_map = prev_info
                .entry(metrics.router_name.clone())
                .or_insert_with(HashMap::new);
            for (peer_labels, info_labels) in &current_peer_info {
                if let Some(old) = prev_map.get(peer_labels) {
                    if old != info_labels {
                        self.wireguard_peer_info.get_or_create(old).set(0);
                    }
                }
            }
            let stale_peers: Vec<_> = prev_map
                .keys()
                .filter(|labels| !current_peer_info.contains_key(*labels))
                .cloned()
                .collect();
            for stale in stale_peers {
                if let Some(old) = prev_map.get(&stale) {
                    self.wireguard_peer_info.get_or_create(old).set(0);
                }
            }
            *prev_map = current_peer_info;
        }
    }
}
