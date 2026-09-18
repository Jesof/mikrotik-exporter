// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Startup connectivity checks and policy handling.

use crate::config::Config;
use crate::prelude::Result;

mod check;
mod policy;

pub(crate) use check::test_router_connectivity;
use policy::enforce_startup_connectivity_policy;

/// Execute startup connectivity checks according to configuration policy.
///
/// # Errors
/// Returns `AppError::Config` when strict startup mode is enabled and
/// at least one router is unreachable.
pub async fn run_startup_connectivity_tests(config: &Config) -> Result<()> {
    config.validate()?;
    if !config.startup_connectivity_test || config.routers.is_empty() {
        return Ok(());
    }

    tracing::info!(
        timeout_secs = config.startup_connectivity_timeout_secs,
        strict = config.strict_startup_mode,
        "Performing startup connectivity tests"
    );

    let failed_routers =
        test_router_connectivity(config, config.startup_connectivity_timeout_secs).await;

    if failed_routers.is_empty() {
        tracing::info!("All router connectivity tests passed");
        return Ok(());
    }

    tracing::warn!(
        failed_count = failed_routers.len(),
        failed_routers = ?failed_routers,
        "Startup connectivity test failed"
    );

    enforce_startup_connectivity_policy(&failed_routers, config.strict_startup_mode)
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    use super::*;

    #[tokio::test]
    async fn test_run_startup_connectivity_tests_disabled_returns_ok() {
        let config = Config::default();
        let result = run_startup_connectivity_tests(&config).await;
        assert!(result.is_ok());
    }
}
