// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Cleanup helpers: delegates to domain modules.

use std::collections::HashSet;
use std::time::Duration;
use tokio::time::Instant;

use super::MetricsRegistry;

impl MetricsRegistry {
    /// Clean up stale dynamic labels based on TTL to prevent unbounded growth
    pub fn cleanup_expired_dynamic_labels(&self, ttl: Duration) {
        let now = Instant::now();
        self.system.cleanup_expired_info(now, ttl);
        self.conntrack.cleanup_expired(now, ttl);
        self.wireguard.cleanup_expired(now, ttl);
        self.certificate.cleanup_expired(now, ttl);
        self.firewall.cleanup_expired_rules(now, ttl);
        self.interface.cleanup_expired_info(now, ttl);
        self.wireguard.cleanup_expired_info(now, ttl);
        self.firewall.cleanup_expired_info(now, ttl);
    }

    /// Clean up cached state for routers that are no longer configured
    pub fn cleanup_stale_routers(&self, active_routers: &HashSet<String>) {
        // Retain only active routers in last_seen maps
        self.system.retain_active_last_seen(active_routers);
        self.interface.retain_active_last_seen(active_routers);
        self.wireguard.retain_active_last_seen(active_routers);
        self.firewall.retain_active_last_seen(active_routers);

        // Find stale routers
        let mut stale_routers: HashSet<_> = self
            .known_routers
            .iter()
            .filter(|entry| !active_routers.contains(entry.key()))
            .map(|entry| entry.key().clone())
            .collect();

        // Collect additional stale routers from domain state
        for key in self.system.prev_info.iter() {
            if !active_routers.contains(key.key()) {
                stale_routers.insert(key.key().clone());
            }
        }
        for key in self.interface.prev_info.iter() {
            if !active_routers.contains(key.key()) {
                stale_routers.insert(key.key().clone());
            }
        }
        for key in self.conntrack.prev.iter() {
            if !active_routers.contains(key.key()) {
                stale_routers.insert(key.key().clone());
            }
        }
        for key in self.wireguard.prev_peers.iter() {
            if !active_routers.contains(key.key()) {
                stale_routers.insert(key.key().clone());
            }
        }
        for key in self.certificate.prev.iter() {
            if !active_routers.contains(key.key()) {
                stale_routers.insert(key.key().clone());
            }
        }
        for key in self.firewall.prev_rules_by_router.iter() {
            if !active_routers.contains(key.key()) {
                stale_routers.insert(key.key().clone());
            }
        }

        // Remove all stale router metrics
        for router in &stale_routers {
            let labels = crate::metrics::labels::RouterLabels {
                router: router.clone(),
            };
            self.interface.cleanup_stale_router(router);
            self.system.cleanup_stale_router(router);
            self.conntrack.cleanup_stale_router(router);
            self.wireguard.cleanup_stale_router(router);
            self.certificate.cleanup_stale_router(router);
            self.firewall.cleanup_stale_router(router);
            self.scrape.cleanup_stale_router(router);
            // Conntrack per-router gauges not handled by individual domains
            self.conntrack.dropped_series.remove(&labels);
            self.conntrack.active_series.remove(&labels);
            self.conntrack.update_duration_seconds.remove(&labels);
            self.known_routers.remove(router);
            self.collected_routers.remove(router);
        }
    }
}
