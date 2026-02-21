// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Metric update logic for router snapshots

use crate::metrics::labels::{
    CertificateLabels, ConntrackLabels, FirewallRuleLabels, InterfaceLabels, RouterLabels,
    SystemInfoLabels, WireGuardInterfaceLabels, WireGuardPeerInfoLabels, WireGuardPeerLabels,
};
use crate::metrics::parsers::parse_uptime_to_seconds;
use crate::mikrotik::{RouterMetrics, WireGuardPeerStats};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use super::{InterfaceSnapshot, MetricsRegistry};

#[derive(Clone, Copy)]
enum UpdateMode {
    Normal,
    BaselineOnly,
}

impl UpdateMode {
    fn apply_counters(self) -> bool {
        matches!(self, UpdateMode::Normal)
    }
}

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
        self.update_metrics_with_mode(metrics, UpdateMode::Normal)
            .await;
    }

    /// Update metrics but skip counter increments (baseline only).
    pub async fn update_metrics_baseline(&self, metrics: &RouterMetrics) {
        self.update_metrics_with_mode(metrics, UpdateMode::BaselineOnly)
            .await;
    }

    async fn update_metrics_with_mode(&self, metrics: &RouterMetrics, mode: UpdateMode) {
        let apply_counters = mode.apply_counters();
        {
            for iface in &metrics.interfaces {
                let labels = InterfaceLabels {
                    router: metrics.router_name.clone(),
                    interface: iface.name.clone(),
                };
                if apply_counters {
                    let is_first_collection = !self.prev_iface.contains_key(&labels);

                    if is_first_collection {
                        self.interface_rx_bytes
                            .get_or_create(&labels)
                            .inc_by(iface.rx_bytes);
                        self.interface_tx_bytes
                            .get_or_create(&labels)
                            .inc_by(iface.tx_bytes);
                        self.interface_rx_packets
                            .get_or_create(&labels)
                            .inc_by(iface.rx_packets);
                        self.interface_tx_packets
                            .get_or_create(&labels)
                            .inc_by(iface.tx_packets);
                        self.interface_rx_errors
                            .get_or_create(&labels)
                            .inc_by(iface.rx_errors);
                        self.interface_tx_errors
                            .get_or_create(&labels)
                            .inc_by(iface.tx_errors);
                    } else if let Some(snapshot) = self.prev_iface.get(&labels) {
                        let snapshot = *snapshot.value();
                        let dx_rx_bytes = if iface.rx_bytes >= snapshot.rx_bytes {
                            iface.rx_bytes - snapshot.rx_bytes
                        } else {
                            iface.rx_bytes
                        };
                        let dx_tx_bytes = if iface.tx_bytes >= snapshot.tx_bytes {
                            iface.tx_bytes - snapshot.tx_bytes
                        } else {
                            iface.tx_bytes
                        };
                        let dx_rx_packets = if iface.rx_packets >= snapshot.rx_packets {
                            iface.rx_packets - snapshot.rx_packets
                        } else {
                            iface.rx_packets
                        };
                        let dx_tx_packets = if iface.tx_packets >= snapshot.tx_packets {
                            iface.tx_packets - snapshot.tx_packets
                        } else {
                            iface.tx_packets
                        };
                        let dx_rx_errors = if iface.rx_errors >= snapshot.rx_errors {
                            iface.rx_errors - snapshot.rx_errors
                        } else {
                            iface.rx_errors
                        };
                        let dx_tx_errors = if iface.tx_errors >= snapshot.tx_errors {
                            iface.tx_errors - snapshot.tx_errors
                        } else {
                            iface.tx_errors
                        };
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
                    }
                } else {
                    let _ = self.interface_rx_bytes.get_or_create(&labels);
                    let _ = self.interface_tx_bytes.get_or_create(&labels);
                    let _ = self.interface_rx_packets.get_or_create(&labels);
                    let _ = self.interface_tx_packets.get_or_create(&labels);
                    let _ = self.interface_rx_errors.get_or_create(&labels);
                    let _ = self.interface_tx_errors.get_or_create(&labels);
                }

                self.interface_running
                    .get_or_create(&labels)
                    .set(i64::from(iface.running));
                self.prev_iface.insert(
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
            if let Some(old) = self.prev_system_info.get(&metrics.router_name) {
                if *old.value() != info_labels {
                    self.system_info.get_or_create(old.value()).set(0);
                }
            }
            self.prev_system_info
                .insert(metrics.router_name.clone(), info_labels.clone());
        }
        self.system_info.get_or_create(&info_labels).set(1);

        // Update connection tracking metrics
        let now = Instant::now();
        let mut current_conntrack = HashSet::new();
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
            self.conntrack_last_seen.insert(ct_labels, now);
        }
        {
            let mut prev_map_entry = self
                .prev_conntrack
                .entry(metrics.router_name.clone())
                .or_default();
            let prev_labels = prev_map_entry.value_mut();
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
                        > existing.rx_bytes.saturating_add(existing.rx_bytes)
                }
            }
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => {
                candidate.rx_bytes.saturating_add(candidate.tx_bytes)
                    > existing.rx_bytes.saturating_add(existing.rx_bytes)
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
            self.wireguard_peer_last_seen.insert(wg_peer_labels, now);
            self.wireguard_peer_info_last_seen.insert(info_labels, now);
        }

        {
            let mut prev_peers_entry = self
                .prev_wireguard_peers
                .entry(metrics.router_name.clone())
                .or_default();
            let prev_labels = prev_peers_entry.value_mut();
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
            let mut prev_info_entry = self
                .prev_wireguard_peer_info
                .entry(metrics.router_name.clone())
                .or_default();
            let prev_map = prev_info_entry.value_mut();
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

        // Update certificate metrics
        let now = Instant::now();
        let mut current_certificates = HashSet::new();
        for cert in &metrics.certificate_stats {
            let cert_labels = CertificateLabels {
                router: metrics.router_name.clone(),
                name: cert.name.clone(),
            };
            current_certificates.insert(cert_labels.clone());
            #[allow(clippy::cast_possible_wrap)]
            self.certificate_days_until_expiry
                .get_or_create(&cert_labels)
                .set(cert.days_until_expiry);
            self.certificate_last_seen.insert(cert_labels, now);
        }
        {
            let mut prev_certs_entry = self
                .prev_certificates
                .entry(metrics.router_name.clone())
                .or_default();
            let prev_labels = prev_certs_entry.value_mut();
            for stale in prev_labels.difference(&current_certificates) {
                self.certificate_days_until_expiry
                    .get_or_create(stale)
                    .set(0);
            }
            *prev_labels = current_certificates;
        }

        // Update firewall rule metrics
        let now = Instant::now();
        let mut current_firewall_rules = HashSet::new();
        for rule in &metrics.firewall_rules {
            let rule_labels = FirewallRuleLabels {
                router: metrics.router_name.clone(),
                rule_id: rule.id.clone(),
                chain: rule.chain.clone(),
                action: rule.action.clone(),
                ip_version: rule.ip_version.clone(),
                section: rule.section.clone(),
            };
            current_firewall_rules.insert(rule_labels.clone());

            if apply_counters {
                let is_first_collection = !self.prev_firewall_rules.contains_key(&rule_labels);

                if is_first_collection {
                    self.firewall_rule_bytes
                        .get_or_create(&rule_labels)
                        .inc_by(rule.bytes);
                    self.firewall_rule_packets
                        .get_or_create(&rule_labels)
                        .inc_by(rule.packets);
                } else if let Some(prev_entry) = self.prev_firewall_rules.get(&rule_labels) {
                    let (prev_bytes, prev_packets) = *prev_entry.value();

                    let dx_bytes = if rule.bytes >= prev_bytes {
                        rule.bytes - prev_bytes
                    } else {
                        rule.bytes
                    };

                    let dx_packets = if rule.packets >= prev_packets {
                        rule.packets - prev_packets
                    } else {
                        rule.packets
                    };

                    self.firewall_rule_bytes
                        .get_or_create(&rule_labels)
                        .inc_by(dx_bytes);
                    self.firewall_rule_packets
                        .get_or_create(&rule_labels)
                        .inc_by(dx_packets);
                }
            } else {
                let _ = self.firewall_rule_bytes.get_or_create(&rule_labels);
                let _ = self.firewall_rule_packets.get_or_create(&rule_labels);
            }

            // Store current values for next iteration
            self.prev_firewall_rules
                .insert(rule_labels.clone(), (rule.bytes, rule.packets));
            self.firewall_rule_last_seen.insert(rule_labels, now);
        }

        // Clean up stale firewall rules for this router
        {
            let mut prev_firewall_rules_entry = self
                .prev_firewall_rules_by_router
                .entry(metrics.router_name.clone())
                .or_default();
            let prev_labels = prev_firewall_rules_entry.value_mut();
            for stale in prev_labels.difference(&current_firewall_rules) {
                // Reset counters for stale labels
                self.firewall_rule_bytes.get_or_create(stale).inc_by(0);
                self.firewall_rule_packets.get_or_create(stale).inc_by(0);
                // Remove from tracking maps
                self.prev_firewall_rules.remove(stale);
                self.firewall_rule_last_seen.remove(stale);
            }
            *prev_labels = current_firewall_rules;
        }
    }
}
