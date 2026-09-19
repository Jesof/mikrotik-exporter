// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Benchmarks for applying router snapshots to the metrics registry.

use criterion::{Criterion, criterion_group, criterion_main};
use mikrotik_exporter::{MetricsRegistry, RouterLabels};

mod common;

fn bench_update_metrics(c: &mut Criterion) {
    let registry = MetricsRegistry::new();
    let metrics = common::router_metrics(0);
    registry.initialize_router_metrics(&RouterLabels {
        router: metrics.router_name.clone(),
    });

    c.bench_function("update_metrics_full_snapshot", |b| {
        b.iter(|| registry.update_metrics(std::hint::black_box(&metrics)));
    });

    let mut metrics_interface_only = metrics.clone();
    metrics_interface_only.connection_tracking.clear();
    metrics_interface_only.wireguard_peers.clear();
    metrics_interface_only.firewall_rules.clear();
    metrics_interface_only.certificate_stats.clear();

    c.bench_function("update_metrics_interfaces_only", |b| {
        b.iter(|| registry.update_metrics(std::hint::black_box(&metrics_interface_only)));
    });
}

criterion_group!(benches, bench_update_metrics);
criterion_main!(benches);
