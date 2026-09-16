// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use crate::config::RouterConfig;
use crate::metrics::{MetricsRegistry, RouterLabels};
use crate::mikrotik::{ConnectionPool, MikroTikClient, RouterMetrics};
use secrecy::ExposeSecret;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

pub(super) async fn collect_router(
    router: &RouterConfig,
    pool: &Arc<ConnectionPool>,
    metrics: &MetricsRegistry,
    gap_reset_threshold: Duration,
) {
    let client = MikroTikClient::with_pool(router.clone(), pool.clone());
    let labels = RouterLabels {
        router: router.name.clone(),
    };
    let start = Instant::now();
    match client.collect_metrics().await {
        Ok(snapshot) => apply_snapshot(metrics, &labels, &snapshot, gap_reset_threshold),
        Err(error) => {
            metrics.record_scrape_error(&labels);
            tracing::warn!(router = %router.name, %error, "Failed to collect metrics");
        }
    }
    metrics.record_scrape_duration(&labels, start.elapsed().as_secs_f64());
    // A `None` group matches every group for this router identity, so the max
    // consecutive error count is already aggregated.
    let errors = pool
        .get_connection_state(
            &router.address,
            &router.username,
            router.password.expose_secret(),
            router.tls.as_ref(),
            None,
        )
        .await
        .map_or(0, |(count, _)| count);
    metrics.update_connection_errors(&labels, errors);
}

fn apply_snapshot(
    metrics: &MetricsRegistry,
    labels: &RouterLabels,
    snapshot: &RouterMetrics,
    gap_reset_threshold: Duration,
) {
    if !snapshot.collection_status.all_ok() {
        metrics.record_scrape_error(labels);
        metrics.update_metrics(snapshot);
        return;
    }
    let gap =
        metrics.record_scrape_success_and_check_gap(labels, Instant::now(), gap_reset_threshold);
    if gap.is_some() {
        metrics.update_metrics_baseline(snapshot);
    } else {
        metrics.update_metrics(snapshot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mikrotik::{CollectionStatus, CollectionStatusParts, FetchState};

    #[tokio::test]
    async fn test_partial_scrape_preserves_group_states_without_full_success() {
        let metrics = MetricsRegistry::new();
        let labels = RouterLabels {
            router: "r1".into(),
        };
        let snapshot = RouterMetrics {
            router_name: labels.router.clone(),
            collection_status: CollectionStatus::from_parts(CollectionStatusParts {
                system_interfaces: FetchState::Complete,
                conntrack: FetchState::Partial,
                wireguard: FetchState::Failed,
                certificates: FetchState::Complete,
                firewall: FetchState::Complete,
            }),
            ..RouterMetrics::default()
        };
        apply_snapshot(&metrics, &labels, &snapshot, Duration::from_secs(60));
        assert_eq!(metrics.get_scrape_success_count(&labels), 0);
        assert_eq!(metrics.get_scrape_error_count(&labels), 1);
        assert!(metrics.get_last_scrape_success_age("r1").is_none());
        let encoded = metrics.encode_metrics().await.unwrap();
        assert!(encoded.contains(
            "mikrotik_group_collection_success{router=\"r1\",group=\"system_interfaces\"} 1"
        ));
        assert!(
            encoded.contains(
                "mikrotik_group_collection_complete{router=\"r1\",group=\"conntrack\"} 0"
            )
        );
        assert!(
            encoded
                .contains("mikrotik_group_collection_success{router=\"r1\",group=\"wireguard\"} 0")
        );
    }

    #[test]
    fn test_complete_empty_interfaces_snapshot_counts_as_success() {
        let metrics = MetricsRegistry::new();
        let labels = RouterLabels {
            router: "r1".into(),
        };
        let snapshot = RouterMetrics {
            router_name: labels.router.clone(),
            ..RouterMetrics::default()
        };
        apply_snapshot(&metrics, &labels, &snapshot, Duration::from_secs(60));
        assert_eq!(metrics.get_scrape_success_count(&labels), 1);
        assert_eq!(metrics.get_scrape_error_count(&labels), 0);
    }
}
