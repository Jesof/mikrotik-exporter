// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Certificate metrics domain.

use crate::metrics::labels::CertificateLabels;
use crate::mikrotik::CertificateStats;
use dashmap::DashMap;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::time::Instant;

#[derive(Clone)]
pub(crate) struct CertificateDomain {
    pub(crate) days_until_expiry: Family<CertificateLabels, Gauge>,
    pub(crate) prev: Arc<DashMap<String, HashSet<CertificateLabels>>>,
    pub(crate) last_seen: Arc<DashMap<CertificateLabels, Instant>>,
}

impl CertificateDomain {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let days_until_expiry = Family::<CertificateLabels, Gauge>::default();
        registry.register(
            "mikrotik_certificate_days_until_expiry",
            "Days until certificate expiry",
            days_until_expiry.clone(),
        );

        Self {
            days_until_expiry,
            prev: Arc::new(DashMap::new()),
            last_seen: Arc::new(DashMap::new()),
        }
    }

    pub(crate) fn update(&self, router_name: &str, certificate_stats: &[CertificateStats]) {
        let mut current_certificates = HashSet::new();
        let now = Instant::now();

        for cert in certificate_stats {
            let labels = CertificateLabels {
                router: router_name.into(),
                id: cert.id.clone(),
                name: cert.name.clone(),
            };

            current_certificates.insert(labels.clone());
            self.days_until_expiry
                .get_or_create(&labels)
                .set(cert.days_until_expiry);
            self.last_seen.insert(labels, now);
        }

        let mut prev_certs_entry = self.prev.entry(router_name.into()).or_default();
        let prev_labels = prev_certs_entry.value_mut();
        for stale in prev_labels.difference(&current_certificates) {
            self.days_until_expiry.remove(stale);
            self.last_seen.remove(stale);
        }
        *prev_labels = current_certificates;
    }

    pub(crate) fn cleanup_expired(&self, now: Instant, ttl: std::time::Duration) {
        let stale: Vec<CertificateLabels> = self
            .last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();

        for label in &stale {
            self.last_seen.remove(label);
        }
        if !stale.is_empty() {
            let count = stale.len();
            for label in &stale {
                if let Some(mut set) = self.prev.get_mut(&label.router) {
                    set.remove(label);
                }
                self.days_until_expiry.remove(label);
            }
            tracing::debug!(
                expired = count,
                "Expired certificate labels via TTL cleanup"
            );
        }
    }

    pub(crate) fn cleanup_stale_router(&self, router_name: &str) {
        if let Some((_, set)) = self.prev.remove(router_name) {
            for label in &set {
                self.days_until_expiry.remove(label);
                self.last_seen.remove(label);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::metrics::registry::MetricsRegistry;
    use crate::metrics::registry::test_support::*;
    use crate::mikrotik::{CertificateStats, FetchState};

    #[tokio::test]
    async fn test_certificates_preserved_when_only_wireguard_updates() {
        let registry = MetricsRegistry::new();
        let iface = make_interface("*1", "ether1", "", 1000, 2000, 10, 20, 0, 0, true);
        let system = make_system("7.10", "RB750Gr3", "1d");

        let mut metrics_full = make_router_metrics("router1", vec![iface.clone()], system.clone());
        metrics_full.wireguard_peers = vec![make_wireguard_peer("*wg1", 100, 200, Some(1000))];
        metrics_full.certificate_stats = vec![CertificateStats {
            id: "*cert1".to_string(),
            name: "cert1".to_string(),
            days_until_expiry: 30,
        }];
        registry.update_metrics(&metrics_full);

        let mut metrics_partial = make_router_metrics("router1", vec![iface], system);
        metrics_partial.collection_status = make_partial_status(
            FetchState::Failed,
            FetchState::Complete,
            FetchState::Failed,
            FetchState::Failed,
        );
        metrics_partial.wireguard_peers = vec![make_wireguard_peer("*wg1", 500, 700, Some(2000))];
        registry.update_metrics(&metrics_partial);

        let cert_labels = crate::metrics::labels::CertificateLabels {
            router: "router1".to_string(),
            id: "*cert1".to_string(),
            name: "cert1".to_string(),
        };
        assert_eq!(
            registry
                .certificate
                .days_until_expiry
                .get_or_create(&cert_labels)
                .get(),
            30,
            "Certificate metric should not be removed when certificate fetch failed"
        );
    }
}
