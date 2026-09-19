// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Firewall metrics domain.

use crate::metrics::labels::{FirewallRuleInfoLabels, FirewallRuleLabels};
use crate::mikrotik::FirewallRuleStats;
use dashmap::DashMap;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::time::Instant;

#[derive(Clone)]
pub(crate) struct FirewallDomain {
    pub(crate) rule_bytes: Family<FirewallRuleLabels, Counter>,
    pub(crate) rule_packets: Family<FirewallRuleLabels, Counter>,
    pub(crate) rule_info: Family<FirewallRuleInfoLabels, Gauge>,
    pub(crate) prev_rules: Arc<DashMap<FirewallRuleLabels, (u64, u64)>>,
    pub(crate) prev_rules_by_router: Arc<DashMap<String, HashSet<FirewallRuleLabels>>>,
    pub(crate) prev_rule_info:
        Arc<DashMap<String, HashMap<FirewallRuleLabels, FirewallRuleInfoLabels>>>,
    pub(crate) rule_last_seen: Arc<DashMap<FirewallRuleLabels, Instant>>,
    pub(crate) rule_info_last_seen: Arc<DashMap<FirewallRuleInfoLabels, Instant>>,
    seeded_routers: Arc<DashMap<String, ()>>,
}

impl FirewallDomain {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let rule_bytes = Family::<FirewallRuleLabels, Counter>::default();
        registry.register(
            "mikrotik_firewall_rule_bytes",
            "Bytes matched by firewall rule",
            rule_bytes.clone(),
        );
        let rule_packets = Family::<FirewallRuleLabels, Counter>::default();
        registry.register(
            "mikrotik_firewall_rule_packets",
            "Packets matched by firewall rule",
            rule_packets.clone(),
        );
        let rule_info = Family::<FirewallRuleInfoLabels, Gauge>::default();
        registry.register(
            "mikrotik_firewall_rule_info",
            "Static firewall rule info (value=1)",
            rule_info.clone(),
        );

        Self {
            rule_bytes,
            rule_packets,
            rule_info,
            prev_rules: Arc::new(DashMap::new()),
            prev_rules_by_router: Arc::new(DashMap::new()),
            prev_rule_info: Arc::new(DashMap::new()),
            rule_last_seen: Arc::new(DashMap::new()),
            rule_info_last_seen: Arc::new(DashMap::new()),
            seeded_routers: Arc::new(DashMap::new()),
        }
    }

    #[allow(clippy::fn_params_excessive_bools)]
    pub(crate) fn update(
        &self,
        router_name: &str,
        firewall_rules: &[FirewallRuleStats],
        firewall_ok: bool,
        firewall_complete_ok: bool,
        apply_counters: bool,
    ) {
        if !firewall_ok {
            tracing::debug!(router = %router_name, "Skipping firewall metric update due to partial collection");
            return;
        }

        // Seed cumulative counters on the first usable collection of this
        // domain, not on the first snapshot of the router: a router whose first
        // snapshot had the firewall group failed must still seed the cumulative
        // values when the group first succeeds, instead of starting from zero.
        let seed_cumulative = apply_counters && !self.seeded_routers.contains_key(router_name);
        let mut current_firewall_rules = HashSet::new();
        let mut current_firewall_info = HashMap::new();
        let now = Instant::now();

        for rule in firewall_rules {
            let labels = FirewallRuleLabels {
                router: router_name.into(),
                id: rule.id.clone(),
                chain: rule.chain.clone(),
                action: rule.action.clone(),
                ip_version: rule.ip_version.clone(),
                section: rule.section.clone(),
            };
            let info_labels = FirewallRuleInfoLabels {
                router: router_name.into(),
                id: rule.id.clone(),
                ip_version: rule.ip_version.clone(),
                section: rule.section.clone(),
                comment: rule.comment.clone(),
            };

            current_firewall_rules.insert(labels.clone());
            current_firewall_info.insert(labels.clone(), info_labels.clone());

            if apply_counters {
                let is_first_collection = !self.prev_rules.contains_key(&labels);

                if is_first_collection {
                    let bytes = self.rule_bytes.get_or_create(&labels);
                    let packets = self.rule_packets.get_or_create(&labels);
                    if seed_cumulative {
                        bytes.inc_by(rule.bytes);
                        packets.inc_by(rule.packets);
                    }
                } else if let Some(prev_entry) = self.prev_rules.get(&labels) {
                    let (prev_bytes, prev_packets) = *prev_entry.value();

                    self.rule_bytes
                        .get_or_create(&labels)
                        .inc_by(counter_delta(rule.bytes, prev_bytes));

                    self.rule_packets
                        .get_or_create(&labels)
                        .inc_by(counter_delta(rule.packets, prev_packets));
                }
            } else {
                let _ = self.rule_bytes.get_or_create(&labels);
                let _ = self.rule_packets.get_or_create(&labels);
            }

            self.rule_info.get_or_create(&info_labels).set(1);

            self.prev_rules
                .insert(labels.clone(), (rule.bytes, rule.packets));
            self.rule_last_seen.insert(labels.clone(), now);
            self.rule_info_last_seen.insert(info_labels, now);
        }

        let mut prev_rules_entry = self
            .prev_rules_by_router
            .entry(router_name.into())
            .or_default();
        let prev_labels = prev_rules_entry.value_mut();
        if !firewall_complete_ok {
            for labels in prev_labels.iter() {
                current_firewall_rules.insert(labels.clone());
                self.rule_last_seen.insert(labels.clone(), now);
            }
        }
        for stale in prev_labels.difference(&current_firewall_rules) {
            self.rule_bytes.remove(stale);
            self.rule_packets.remove(stale);
            self.rule_last_seen.remove(stale);
            self.prev_rules.remove(stale);
        }
        *prev_labels = current_firewall_rules;

        let mut prev_info_entry = self.prev_rule_info.entry(router_name.into()).or_default();
        let prev_map = prev_info_entry.value_mut();
        if !firewall_complete_ok {
            for (labels, info_labels) in prev_map.iter() {
                current_firewall_info
                    .entry(labels.clone())
                    .or_insert_with(|| info_labels.clone());
                self.rule_info_last_seen.insert(info_labels.clone(), now);
            }
        }
        for (labels, info_labels) in prev_map.iter() {
            if !current_firewall_info.contains_key(labels) {
                self.rule_info.remove(info_labels);
                self.rule_info_last_seen.remove(info_labels);
            } else if let Some(current_info) = current_firewall_info.get(labels)
                && current_info != info_labels
            {
                self.rule_info.get_or_create(info_labels).set(0);
            }
        }
        *prev_map = current_firewall_info;

        if apply_counters {
            self.seeded_routers.insert(router_name.into(), ());
        }
    }

    pub(crate) fn cleanup_expired_rules(&self, now: Instant, ttl: std::time::Duration) {
        let stale: Vec<FirewallRuleLabels> = self
            .rule_last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();

        for label in &stale {
            self.rule_last_seen.remove(label);
        }
        if !stale.is_empty() {
            let count = stale.len();
            for label in &stale {
                if let Some(mut set) = self.prev_rules_by_router.get_mut(&label.router) {
                    set.remove(label);
                }
                self.prev_rules.remove(label);
                self.rule_bytes.remove(label);
                self.rule_packets.remove(label);

                if let Some(mut map) = self.prev_rule_info.get_mut(&label.router)
                    && let Some(info_label) = map.remove(label)
                {
                    self.rule_info.remove(&info_label);
                    self.rule_info_last_seen.remove(&info_label);
                }
            }
            tracing::debug!(
                expired = count,
                "Expired firewall rule labels via TTL cleanup"
            );
        }
    }

    pub(crate) fn cleanup_expired_info(&self, now: Instant, ttl: std::time::Duration) {
        let stale: Vec<FirewallRuleInfoLabels> = self
            .rule_info_last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();
        if !stale.is_empty() {
            let count = stale.len();
            for label in stale {
                self.rule_info_last_seen.remove(&label);
                self.rule_info.remove(&label);
            }
            tracing::debug!(
                expired = count,
                "Expired firewall rule info labels via TTL cleanup"
            );
        }
    }

    pub(crate) fn cleanup_stale_router(&self, router_name: &str) {
        if let Some((_, set)) = self.prev_rules_by_router.remove(router_name) {
            for label in &set {
                self.prev_rules.remove(label);
                self.rule_bytes.remove(label);
                self.rule_packets.remove(label);
                self.rule_last_seen.remove(label);
            }
        }
        if let Some((_, map)) = self.prev_rule_info.remove(router_name) {
            for info_label in map.values() {
                self.rule_info.remove(info_label);
                self.rule_info_last_seen.remove(info_label);
            }
        }
        self.seeded_routers.remove(router_name);
    }

    pub(crate) fn retain_active_last_seen(
        &self,
        active_routers: &std::collections::HashSet<String>,
    ) {
        self.rule_info_last_seen.retain(|labels, _| {
            if active_routers.contains(&labels.router) {
                true
            } else {
                self.rule_info.remove(labels);
                false
            }
        });
    }
}

#[inline]
fn counter_delta(current: u64, previous: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use crate::metrics::registry::MetricsRegistry;
    use crate::metrics::registry::test_support::*;
    use crate::mikrotik::FetchState;
    use tokio::time::Instant;

    #[tokio::test]
    async fn test_firewall_partial_snapshot_preserves_previous_rules() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("*1", "ether1", "", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d");

        let mut metrics_full = make_router_metrics("router1", vec![iface.clone()], system.clone());
        metrics_full.firewall_rules = vec![
            make_firewall_rule("*f1", 1000, 10),
            make_firewall_rule("*f2", 2000, 20),
        ];
        registry.update_metrics(&metrics_full);

        let mut metrics_partial = make_router_metrics("router1", vec![iface], system);
        metrics_partial.collection_status = make_partial_status(
            FetchState::Failed,
            FetchState::Failed,
            FetchState::Failed,
            FetchState::Partial,
        );
        metrics_partial.firewall_rules = vec![make_firewall_rule("*f1", 1500, 15)];
        registry.update_metrics(&metrics_partial);

        let stale_rule_labels = crate::metrics::labels::FirewallRuleLabels {
            router: "router1".to_string(),
            id: "*f2".to_string(),
            chain: "forward".to_string(),
            action: "accept".to_string(),
            ip_version: "ipv4".to_string(),
            section: "filter".to_string(),
        };

        assert_eq!(
            registry
                .firewall
                .rule_bytes
                .get_or_create(&stale_rule_labels)
                .get(),
            2000,
            "Stale firewall rule should be preserved during partial firewall snapshot"
        );
    }

    #[tokio::test]
    async fn test_firewall_first_usable_snapshot_seeds_after_failed_start() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("*1", "ether1", "WAN", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d");
        let mut failed = make_router_metrics("r1", vec![iface.clone()], system.clone());
        failed.collection_status = make_partial_status(
            FetchState::Complete,
            FetchState::Complete,
            FetchState::Complete,
            FetchState::Failed,
        );
        registry.update_metrics(&failed);

        let mut succeeded = make_router_metrics("r1", vec![iface], system);
        succeeded.firewall_rules = vec![make_firewall_rule("*f1", 5000, 50)];
        registry.update_metrics(&succeeded);

        let stale_rule_labels = crate::metrics::labels::FirewallRuleLabels {
            router: "r1".into(),
            id: "*f1".into(),
            chain: "forward".into(),
            action: "accept".into(),
            ip_version: "ipv4".into(),
            section: "filter".into(),
        };
        assert_eq!(
            registry
                .firewall
                .rule_bytes
                .get_or_create(&stale_rule_labels)
                .get(),
            5000,
            "first usable firewall snapshot must seed cumulative values even after a failed start"
        );
        registry.cleanup_stale_routers(&std::collections::HashSet::new());
        assert!(
            registry
                .firewall
                .seeded_routers
                .iter()
                .all(|entry| entry.key() != "r1")
        );
    }

    #[tokio::test]
    async fn test_firewall_partial_refreshes_retained_rule_ttl() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("*1", "ether1", "", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d");

        let mut full = make_router_metrics("router1", vec![iface.clone()], system.clone());
        full.firewall_rules = vec![make_firewall_rule("*f1", 1000, 10)];
        registry.update_metrics(&full);

        let rule_labels = crate::metrics::labels::FirewallRuleLabels {
            router: "router1".to_string(),
            id: "*f1".to_string(),
            chain: "forward".to_string(),
            action: "accept".to_string(),
            ip_version: "ipv4".to_string(),
            section: "filter".to_string(),
        };
        registry.firewall.rule_last_seen.insert(
            rule_labels.clone(),
            Instant::now() - std::time::Duration::from_secs(100),
        );

        let mut partial = make_router_metrics("router1", vec![iface], system);
        partial.collection_status = make_partial_status(
            FetchState::Failed,
            FetchState::Failed,
            FetchState::Failed,
            FetchState::Partial,
        );
        partial.firewall_rules = Vec::new();
        registry.update_metrics(&partial);
        registry.cleanup_expired_dynamic_labels(std::time::Duration::from_secs(60));

        assert!(
            registry.firewall.prev_rules.contains_key(&rule_labels),
            "retained firewall rule must survive TTL cleanup"
        );
        assert_eq!(
            registry
                .firewall
                .rule_bytes
                .get_or_create(&rule_labels)
                .get(),
            1000
        );

        let mut recovered =
            make_router_metrics("router1", Vec::new(), make_system("7.10", "RB750Gr3", "1d"));
        recovered.firewall_rules = vec![make_firewall_rule("*f1", 1500, 15)];
        registry.update_metrics(&recovered);
        assert_eq!(
            registry
                .firewall
                .rule_bytes
                .get_or_create(&rule_labels)
                .get(),
            1500
        );
    }
}
