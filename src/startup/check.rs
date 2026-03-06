// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Router connectivity checks used during startup.

use crate::config::Config;
use crate::mikrotik::{ConnectionPool, MikroTikClient};
use std::sync::Arc;
use tokio::time::{Duration, timeout};

/// Test connectivity to all configured routers.
#[must_use]
pub(crate) async fn test_router_connectivity(config: &Config, timeout_secs: u64) -> Vec<String> {
    let pool = Arc::new(ConnectionPool::new());
    let mut failed_routers = Vec::new();

    for router in &config.routers {
        let client = MikroTikClient::with_pool(router.clone(), pool.clone());
        let timeout_duration = Duration::from_secs(timeout_secs);

        match timeout(timeout_duration, client.test_connection()).await {
            Ok(Ok(())) => {
                tracing::info!("Successfully connected to router '{}'", router.name);
            }
            Ok(Err(error)) => {
                tracing::warn!("Failed to connect to router '{}': {}", router.name, error);
                failed_routers.push(router.name.clone());
            }
            Err(_) => {
                tracing::warn!(
                    "Timeout connecting to router '{}' (> {timeout_secs}s)",
                    router.name
                );
                failed_routers.push(router.name.clone());
            }
        }
    }

    failed_routers
}
