// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Benchmarks for `OpenMetrics` text encoding.

use criterion::{Criterion, criterion_group, criterion_main};
use mikrotik_exporter::{MetricsRegistry, RouterLabels};

mod common;

const ROUTERS: usize = 10;

fn bench_encode_metrics(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("failed to build runtime");
    let registry = MetricsRegistry::new();
    for index in 0..ROUTERS {
        let metrics = common::router_metrics(index);
        registry.initialize_router_metrics(&RouterLabels {
            router: metrics.router_name.clone(),
        });
        registry.update_metrics(&metrics);
    }

    c.bench_function("encode_metrics_10_routers", |b| {
        b.iter(|| {
            let encoded = rt.block_on(registry.encode_metrics());
            std::hint::black_box(encoded.expect("encoding failed"));
        });
    });
}

criterion_group!(benches, bench_encode_metrics);
criterion_main!(benches);
