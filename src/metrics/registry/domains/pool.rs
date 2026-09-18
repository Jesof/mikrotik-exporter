// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Connection pool metrics domain.

use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

#[derive(Clone)]
pub(crate) struct PoolDomain {
    pub(crate) size: Gauge,
    pub(crate) active: Gauge,
}

impl PoolDomain {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let size = Gauge::default();
        registry.register(
            "mikrotik_connection_pool_size",
            "Total number of connections in pool",
            size.clone(),
        );
        let active = Gauge::default();
        registry.register(
            "mikrotik_connection_pool_active",
            "Number of active connections in pool",
            active.clone(),
        );
        Self { size, active }
    }

    pub(crate) fn update(&self, total: usize, active: usize) {
        #[allow(clippy::cast_possible_wrap)]
        {
            self.size.set(total as i64);
            self.active.set(active as i64);
        }
    }
}
