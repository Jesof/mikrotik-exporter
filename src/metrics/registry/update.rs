// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Metric update logic: delegates to domain modules.

use crate::mikrotik::RouterMetrics;

use super::MetricsRegistry;

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
    pub fn update_metrics(&self, metrics: &RouterMetrics) {
        self.update_metrics_with_mode(metrics, UpdateMode::Normal);
    }

    /// Update metrics but skip counter increments (baseline only).
    pub fn update_metrics_baseline(&self, metrics: &RouterMetrics) {
        self.update_metrics_with_mode(metrics, UpdateMode::BaselineOnly);
    }

    fn update_metrics_with_mode(&self, metrics: &RouterMetrics, mode: UpdateMode) {
        let router_label = crate::metrics::labels::RouterLabels {
            router: metrics.router_name.clone(),
        };
        self.record_group_status(&router_label, &metrics.collection_status);

        let apply_counters = mode.apply_counters();

        if metrics.collection_status.system_interfaces_ok() {
            self.interface
                .update(&metrics.router_name, &metrics.interfaces, apply_counters);
            self.system.update(&metrics.router_name, &metrics.system);
        }

        self.conntrack.update(
            &metrics.router_name,
            &metrics.connection_tracking,
            metrics.collection_status.conntrack_ok(),
            metrics.collection_status.conntrack_complete_ok(),
        );

        if metrics.collection_status.wireguard_ok() {
            self.wireguard
                .update(&metrics.router_name, &metrics.wireguard_peers);
        }

        if metrics.collection_status.certificates_ok() {
            self.certificate
                .update(
                    &metrics.router_name,
                    &metrics.certificate_stats,
                    metrics.collection_status.certificates_complete_ok(),
                );
        }

        self.firewall.update(
            &metrics.router_name,
            &metrics.firewall_rules,
            metrics.collection_status.firewall_ok(),
            metrics.collection_status.firewall_complete_ok(),
            apply_counters,
        );
    }
}
