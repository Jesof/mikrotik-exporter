// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Startup connectivity policy helpers.

use crate::prelude::{AppError, Result};

pub(crate) fn enforce_startup_connectivity_policy(
    failed_routers: &[String],
    strict_mode: bool,
) -> Result<()> {
    if strict_mode {
        return Err(AppError::Config(format_strict_mode_error(failed_routers)));
    }

    Ok(())
}

pub(crate) fn format_strict_mode_error(failed_routers: &[String]) -> String {
    format!(
        "Strict startup mode: {} router(s) unreachable: {:?}",
        failed_routers.len(),
        failed_routers
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
}
