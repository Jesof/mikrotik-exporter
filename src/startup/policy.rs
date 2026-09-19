// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Startup connectivity policy helpers.

use crate::config::ConfigError;
use crate::prelude::{AppError, Result};

/// Enforces the strict startup connectivity policy.
///
/// # Errors
/// Returns `AppError::Config` when strict mode is enabled and routers failed.
pub(crate) fn enforce_startup_connectivity_policy(
    failed_routers: &[String],
    strict_mode: bool,
) -> Result<()> {
    if strict_mode && !failed_routers.is_empty() {
        return Err(AppError::Config(ConfigError::StrictUnreachable {
            count: failed_routers.len(),
            routers: failed_routers.to_vec(),
        }));
    }

    Ok(())
}

/// Formats the strict-mode unreachable-router error message.
#[cfg(test)]
pub(crate) fn format_strict_mode_error(failed_routers: &[String]) -> String {
    format!(
        "Strict startup mode: {count} router(s) unreachable: {routers:?}",
        count = failed_routers.len(),
        routers = failed_routers
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_strict_policy_accepts_no_failures() {
        assert!(enforce_startup_connectivity_policy(&[], true).is_ok());
    }
}
