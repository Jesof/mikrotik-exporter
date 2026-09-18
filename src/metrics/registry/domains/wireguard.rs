// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! `WireGuard` metrics domain.

use crate::metrics::labels::{WireGuardPeerInfoLabels, WireGuardPeerLabels};
use crate::mikrotik::WireGuardPeerStats;
use dashmap::DashMap;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::time::Instant;

#[derive(Clone)]
pub(crate) struct WireGuardDomain {
    pub(crate) peer_rx_bytes: Family<WireGuardPeerLabels, Gauge>,
    pub(crate) peer_tx_bytes: Family<WireGuardPeerLabels, Gauge>,
    pub(crate) peer_latest_handshake: Family<WireGuardPeerLabels, Gauge>,
    pub(crate) peer_info: Family<WireGuardPeerInfoLabels, Gauge>,
    pub(crate) prev_peers: Arc<DashMap<String, HashSet<WireGuardPeerLabels>>>,
    pub(crate) prev_peer_info:
        Arc<DashMap<String, HashMap<WireGuardPeerLabels, WireGuardPeerInfoLabels>>>,
    pub(crate) peer_last_seen: Arc<DashMap<WireGuardPeerLabels, Instant>>,
    pub(crate) peer_info_last_seen: Arc<DashMap<WireGuardPeerInfoLabels, Instant>>,
}

impl WireGuardDomain {
    #[allow(clippy::similar_names)]
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let peer_rx_bytes = Family::<WireGuardPeerLabels, Gauge>::default();
        registry.register(
            "mikrotik_wireguard_peer_rx_bytes",
            "Bytes received from WireGuard peer",
            peer_rx_bytes.clone(),
        );
        let peer_tx_bytes = Family::<WireGuardPeerLabels, Gauge>::default();
        registry.register(
            "mikrotik_wireguard_peer_tx_bytes",
            "Bytes transmitted to WireGuard peer",
            peer_tx_bytes.clone(),
        );
        let peer_latest_handshake = Family::<WireGuardPeerLabels, Gauge>::default();
        registry.register(
            "mikrotik_wireguard_peer_latest_handshake_timestamp_seconds",
            "Unix timestamp of last handshake with WireGuard peer",
            peer_latest_handshake.clone(),
        );
        let peer_info = Family::<WireGuardPeerInfoLabels, Gauge>::default();
        registry.register(
            "mikrotik_wireguard_peer_info",
            "Static WireGuard peer info (value=1)",
            peer_info.clone(),
        );

        Self {
            peer_rx_bytes,
            peer_tx_bytes,
            peer_latest_handshake,
            peer_info,
            prev_peers: Arc::new(DashMap::new()),
            prev_peer_info: Arc::new(DashMap::new()),
            peer_last_seen: Arc::new(DashMap::new()),
            peer_info_last_seen: Arc::new(DashMap::new()),
        }
    }

    pub(crate) fn update(&self, router_name: &str, wireguard_peers: &[WireGuardPeerStats]) {
        let mut deduped_peers = HashMap::new();
        let should_replace = |existing: &WireGuardPeerStats, candidate: &WireGuardPeerStats| match (
            candidate.latest_handshake,
            existing.latest_handshake,
        ) {
            (Some(candidate_ts), Some(existing_ts)) => {
                if candidate_ts == existing_ts {
                    candidate.rx_bytes.saturating_add(candidate.tx_bytes)
                        > existing.rx_bytes.saturating_add(existing.tx_bytes)
                } else {
                    candidate_ts > existing_ts
                }
            }
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => {
                candidate.rx_bytes.saturating_add(candidate.tx_bytes)
                    > existing.rx_bytes.saturating_add(existing.tx_bytes)
            }
        };
        for wg_peer in wireguard_peers {
            let labels = WireGuardPeerLabels {
                router: router_name.into(),
                id: wg_peer.id.clone(),
            };
            if let Some(existing) = deduped_peers.get(&labels) {
                if should_replace(existing, wg_peer) {
                    deduped_peers.insert(labels, wg_peer.clone());
                }
            } else {
                deduped_peers.insert(labels, wg_peer.clone());
            }
        }

        let mut current_peers = HashSet::new();
        let mut current_peer_info = HashMap::new();
        let now = Instant::now();
        for (labels, wg_peer) in deduped_peers {
            current_peers.insert(labels.clone());
            let endpoint = wg_peer.endpoint.clone().unwrap_or_else(|| "unknown".into());
            let info_labels = WireGuardPeerInfoLabels {
                router: labels.router.clone(),
                id: labels.id.clone(),
                interface: wg_peer.interface.clone(),
                allowed_address: wg_peer.allowed_address.clone(),
                name: wg_peer.name.clone(),
                endpoint,
                comment: wg_peer.comment.clone(),
            };
            current_peer_info.insert(labels.clone(), info_labels.clone());
            #[allow(clippy::cast_possible_wrap)]
            {
                self.peer_rx_bytes
                    .get_or_create(&labels)
                    .set(wg_peer.rx_bytes as i64);
                self.peer_tx_bytes
                    .get_or_create(&labels)
                    .set(wg_peer.tx_bytes as i64);
                if let Some(timestamp) = wg_peer.latest_handshake {
                    self.peer_latest_handshake
                        .get_or_create(&labels)
                        .set(timestamp as i64);
                } else {
                    self.peer_latest_handshake.get_or_create(&labels).set(0);
                }
                self.peer_info.get_or_create(&info_labels).set(1);
            }
            self.peer_last_seen.insert(labels, now);
            self.peer_info_last_seen.insert(info_labels, now);
        }

        let mut prev_peers_entry = self.prev_peers.entry(router_name.into()).or_default();
        let prev_labels = prev_peers_entry.value_mut();
        for stale in prev_labels.difference(&current_peers) {
            self.peer_rx_bytes.remove(stale);
            self.peer_tx_bytes.remove(stale);
            self.peer_latest_handshake.remove(stale);
            self.peer_last_seen.remove(stale);
        }
        *prev_labels = current_peers;

        let mut prev_info_entry = self.prev_peer_info.entry(router_name.into()).or_default();
        let prev_map = prev_info_entry.value_mut();
        for (labels, info_labels) in prev_map.iter() {
            if !current_peer_info.contains_key(labels) {
                self.peer_info.remove(info_labels);
                self.peer_info_last_seen.remove(info_labels);
            } else if let Some(current_info) = current_peer_info.get(labels)
                && current_info != info_labels
            {
                self.peer_info.get_or_create(info_labels).set(0);
            }
        }
        *prev_map = current_peer_info;
    }

    pub(crate) fn cleanup_expired(&self, now: Instant, ttl: std::time::Duration) {
        let stale_peers: Vec<WireGuardPeerLabels> = self
            .peer_last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();

        for label in &stale_peers {
            self.peer_last_seen.remove(label);
        }
        if !stale_peers.is_empty() {
            let count = stale_peers.len();
            for label in &stale_peers {
                if let Some(mut set) = self.prev_peers.get_mut(&label.router) {
                    set.remove(label);
                }
                self.peer_rx_bytes.remove(label);
                self.peer_tx_bytes.remove(label);
                self.peer_latest_handshake.remove(label);

                if let Some(mut map) = self.prev_peer_info.get_mut(&label.router)
                    && let Some(info_label) = map.remove(label)
                {
                    self.peer_info.remove(&info_label);
                    self.peer_info_last_seen.remove(&info_label);
                }
            }
            tracing::debug!(
                expired = count,
                "Expired wireguard peer labels via TTL cleanup"
            );
        }
    }

    pub(crate) fn cleanup_expired_info(&self, now: Instant, ttl: std::time::Duration) {
        let stale: Vec<WireGuardPeerInfoLabels> = self
            .peer_info_last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();
        if !stale.is_empty() {
            let count = stale.len();
            for label in stale {
                self.peer_info_last_seen.remove(&label);
                self.peer_info.remove(&label);
            }
            tracing::debug!(
                expired = count,
                "Expired wireguard peer info labels via TTL cleanup"
            );
        }
    }

    pub(crate) fn cleanup_stale_router(&self, router_name: &str) {
        if let Some((_, set)) = self.prev_peers.remove(router_name) {
            for label in &set {
                self.peer_rx_bytes.remove(label);
                self.peer_tx_bytes.remove(label);
                self.peer_latest_handshake.remove(label);
                self.peer_last_seen.remove(label);
            }
        }
        if let Some((_, map)) = self.prev_peer_info.remove(router_name) {
            for info_label in map.values() {
                self.peer_info.remove(info_label);
                self.peer_info_last_seen.remove(info_label);
            }
        }
    }

    pub(crate) fn retain_active_last_seen(
        &self,
        active_routers: &std::collections::HashSet<String>,
    ) {
        self.peer_info_last_seen.retain(|labels, _| {
            if active_routers.contains(&labels.router) {
                true
            } else {
                self.peer_info.remove(labels);
                false
            }
        });
    }
}
