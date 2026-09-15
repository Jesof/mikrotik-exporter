// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use crate::config::Config;
use crate::mikrotik::{ConnectionPool, MikroTikClient};
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};

#[must_use]
pub(crate) async fn test_router_connectivity(config: &Config, timeout_secs: u64) -> Vec<String> {
    if !(1..=300).contains(&timeout_secs) {
        return config
            .routers
            .iter()
            .map(|router| router.name.clone())
            .collect();
    }
    let pool = Arc::new(ConnectionPool::new());
    let mut tasks = JoinSet::new();
    for router in &config.routers {
        let router = router.clone();
        let pool = pool.clone();
        tasks.spawn(async move {
            let client = MikroTikClient::with_pool(router.clone(), pool);
            let passed = matches!(
                timeout(Duration::from_secs(timeout_secs), client.test_connection()).await,
                Ok(Ok(()))
            );
            (router.name, passed)
        });
    }
    let mut passed = std::collections::HashSet::new();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((name, true)) => {
                passed.insert(name);
            }
            Ok((name, false)) => {
                tracing::warn!(router = %name, "Startup connectivity check failed");
            }
            Err(error) => tracing::error!(%error, "Startup connectivity task failed"),
        }
    }
    config
        .routers
        .iter()
        .filter(|router| !passed.contains(&router.name))
        .map(|router| router.name.clone())
        .collect()
}
