// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Cache for immutable system information

use crate::mikrotik::SystemResource;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Cache for immutable system information (version, board name)
#[derive(Clone, Default)]
pub(super) struct SystemInfoCache {
    cache: Arc<RwLock<HashMap<String, SystemResource>>>,
}

impl SystemInfoCache {
    #[must_use]
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) async fn get(&self, router_name: &str) -> Option<SystemResource> {
        let cache = self.cache.read().await;
        cache.get(router_name).cloned()
    }

    pub(super) async fn set(&self, router_name: String, system: SystemResource) {
        let mut cache = self.cache.write().await;
        tracing::debug!("Cached system info for router: {}", router_name);
        cache.insert(router_name, system);
    }

    pub(super) async fn cleanup_stale(&self, active_routers: &HashSet<String>) {
        let mut cache = self.cache.write().await;
        let before_count = cache.len();
        cache.retain(|router, _| active_routers.contains(router));
        let removed = before_count - cache.len();
        if removed > 0 {
            tracing::debug!("Removed {} stale system info cache entries", removed);
        }
    }
}
