// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Startup connectivity checks and policy handling.

use crate::config::Config;
use crate::mikrotik::{ConnectionPool, MikroTikClient};
use crate::prelude::{AppError, Result};
use std::sync::Arc;
use tokio::time::{Duration, timeout};

/// Test connectivity to all configured routers.
#[must_use]
pub async fn test_router_connectivity(config: &Config, timeout_secs: u64) -> Vec<String> {
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
                    "Timeout connecting to router '{}' (>{timeout_secs}s)",
                    router.name
                );
                failed_routers.push(router.name.clone());
            }
        }
    }

    failed_routers
}

/// Execute startup connectivity checks according to configuration policy.
///
/// # Errors
/// Returns `AppError::Config` when strict startup mode is enabled and
/// at least one router is unreachable.
pub async fn run_startup_connectivity_tests(config: &Config) -> Result<()> {
    if !config.startup_connectivity_test || config.routers.is_empty() {
        return Ok(());
    }

    tracing::info!(
        "Performing startup connectivity tests (timeout: {}s{})",
        config.startup_connectivity_timeout_secs,
        if config.strict_startup_mode {
            ", strict mode enabled"
        } else {
            ""
        }
    );

    let failed_routers =
        test_router_connectivity(config, config.startup_connectivity_timeout_secs).await;

    if failed_routers.is_empty() {
        tracing::info!("All router connectivity tests passed");
        return Ok(());
    }

    tracing::warn!(
        "Connectivity test failed for {} router(s): {:?}",
        failed_routers.len(),
        failed_routers
    );

    enforce_startup_connectivity_policy(&failed_routers, config.strict_startup_mode)
}

fn enforce_startup_connectivity_policy(failed_routers: &[String], strict_mode: bool) -> Result<()> {
    if strict_mode {
        return Err(AppError::Config(format_strict_mode_error(failed_routers)));
    }

    Ok(())
}

fn format_strict_mode_error(failed_routers: &[String]) -> String {
    format!(
        "Strict startup mode: {} router(s) unreachable: {:?}",
        failed_routers.len(),
        failed_routers
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_startup_connectivity_tests_disabled_returns_ok() {
        let config = Config::default();
        let result = run_startup_connectivity_tests(&config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_enforce_startup_connectivity_policy_strict_mode() {
        let failed = vec!["router-a".to_string(), "router-b".to_string()];
        let result = enforce_startup_connectivity_policy(&failed, true);
        assert!(matches!(result, Err(AppError::Config(_))));
    }

    #[test]
    fn test_format_strict_mode_error_contains_router_list() {
        let failed = vec!["router-a".to_string(), "router-b".to_string()];
        let message = format_strict_mode_error(&failed);
        assert_eq!(
            message,
            "Strict startup mode: 2 router(s) unreachable: [\"router-a\", \"router-b\"]"
        );
    }

    #[test]
    fn test_enforce_startup_connectivity_policy_non_strict_mode() {
        let failed = vec!["router-a".to_string()];
        let result = enforce_startup_connectivity_policy(&failed, false);
        assert!(result.is_ok());
    }
}
