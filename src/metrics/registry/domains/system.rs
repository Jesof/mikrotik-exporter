// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! System metrics domain.

use crate::metrics::labels::{RouterLabels, SystemInfoLabels};
use crate::metrics::parsers::parse_uptime_to_seconds;
use crate::mikrotik::SystemResource;
use dashmap::DashMap;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;
use tokio::time::Instant;

type FloatGauge = Gauge<f64, std::sync::atomic::AtomicU64>;

#[derive(Clone)]
pub(crate) struct SystemDomain {
    pub(crate) cpu_load: Family<RouterLabels, FloatGauge>,
    pub(crate) free_memory: Family<RouterLabels, Gauge>,
    pub(crate) total_memory: Family<RouterLabels, Gauge>,
    pub(crate) info: Family<SystemInfoLabels, Gauge>,
    pub(crate) uptime_seconds: Family<RouterLabels, Gauge>,
    pub(crate) prev_info: Arc<DashMap<String, SystemInfoLabels>>,
    pub(crate) info_last_seen: Arc<DashMap<SystemInfoLabels, Instant>>,
}

impl SystemDomain {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let cpu_load = Family::<RouterLabels, FloatGauge>::default();
        registry.register(
            "mikrotik_system_cpu_load_ratio",
            "CPU load ratio (0 to 1)",
            cpu_load.clone(),
        );
        let free_memory = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_free_memory_bytes",
            "Free memory bytes",
            free_memory.clone(),
        );
        let total_memory = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_total_memory_bytes",
            "Total memory bytes",
            total_memory.clone(),
        );
        let info = Family::<SystemInfoLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_info",
            "Static system info (value=1)",
            info.clone(),
        );
        let uptime_seconds = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_uptime_seconds",
            "System uptime in seconds",
            uptime_seconds.clone(),
        );

        Self {
            cpu_load,
            free_memory,
            total_memory,
            info,
            uptime_seconds,
            prev_info: Arc::new(DashMap::new()),
            info_last_seen: Arc::new(DashMap::new()),
        }
    }

    pub(crate) fn update(&self, router_name: &str, system: &SystemResource) {
        let router_label = RouterLabels {
            router: router_name.into(),
        };
        #[allow(clippy::cast_possible_wrap)]
        {
            self.cpu_load
                .get_or_create(&router_label)
                .set(f64::from(u32::try_from(system.cpu_load).unwrap_or(100)) / 100.0);
            self.free_memory
                .get_or_create(&router_label)
                .set(system.free_memory as i64);
            self.total_memory
                .get_or_create(&router_label)
                .set(system.total_memory as i64);
        }
        if let Some(uptime_secs) = parse_uptime_to_seconds(&system.uptime) {
            #[allow(clippy::cast_possible_wrap)]
            self.uptime_seconds
                .get_or_create(&router_label)
                .set(uptime_secs as i64);
        }
        let info_labels = SystemInfoLabels {
            router: router_name.into(),
            version: system.version.clone(),
            board: system.board_name.clone(),
        };
        if let Some(old) = self.prev_info.get(router_name)
            && *old.value() != info_labels
        {
            self.info.get_or_create(old.value()).set(0);
        }
        self.prev_info
            .insert(router_name.into(), info_labels.clone());
        self.info.get_or_create(&info_labels).set(1);
        self.info_last_seen.insert(info_labels, Instant::now());
    }

    pub(crate) fn cleanup_expired_info(&self, now: Instant, ttl: std::time::Duration) {
        let stale: Vec<SystemInfoLabels> = self
            .info_last_seen
            .iter()
            .filter(|entry| now.duration_since(*entry.value()) > ttl)
            .map(|entry| entry.key().clone())
            .collect();
        for labels in stale {
            self.info.remove(&labels);
            self.info_last_seen.remove(&labels);
            self.prev_info
                .remove_if(&labels.router, |_, current| current == &labels);
        }
    }

    pub(crate) fn cleanup_stale_router(&self, router_name: &str) {
        if let Some((_, label)) = self.prev_info.remove(router_name) {
            self.info.remove(&label);
        }
        self.cpu_load.remove(&RouterLabels {
            router: router_name.into(),
        });
        self.free_memory.remove(&RouterLabels {
            router: router_name.into(),
        });
        self.total_memory.remove(&RouterLabels {
            router: router_name.into(),
        });
        self.uptime_seconds.remove(&RouterLabels {
            router: router_name.into(),
        });
    }

    pub(crate) fn retain_active_last_seen(
        &self,
        active_routers: &std::collections::HashSet<String>,
    ) {
        self.info_last_seen.retain(|labels, _| {
            if active_routers.contains(&labels.router) {
                true
            } else {
                self.info.remove(labels);
                false
            }
        });
    }
}
