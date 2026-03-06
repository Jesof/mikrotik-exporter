// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::api::AppState;
use crate::metrics::RouterLabels;

const HEALTHY_MAX_CONSECUTIVE_ERRORS: u32 = 3;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HealthResponse {
    pub(crate) status: String,
    pub(crate) version: String,
    pub(crate) routers: Vec<RouterHealth>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RouterHealth {
    pub(crate) name: String,
    pub(crate) status: String,
    pub(crate) consecutive_errors: u32,
    pub(crate) has_successful_scrape: bool,
}

#[derive(Clone, Copy)]
enum RouterStatus {
    Healthy,
    Degraded,
    Unknown,
}

impl RouterStatus {
    fn as_str(self) -> &'static str {
        match self {
            RouterStatus::Healthy => "healthy",
            RouterStatus::Degraded => "degraded",
            RouterStatus::Unknown => "unknown",
        }
    }
}

fn classify_router_status(
    success_count: u64,
    error_count: u64,
    consecutive_errors: u32,
) -> RouterStatus {
    if success_count > 0 && consecutive_errors < HEALTHY_MAX_CONSECUTIVE_ERRORS {
        RouterStatus::Healthy
    } else if error_count > 0 || consecutive_errors >= HEALTHY_MAX_CONSECUTIVE_ERRORS {
        RouterStatus::Degraded
    } else {
        RouterStatus::Unknown
    }
}

pub(crate) async fn build_health_response(state: &AppState) -> (StatusCode, HealthResponse) {
    let mut routers_health = Vec::new();
    let mut all_healthy = true;

    for router in &state.config.routers {
        let router_label = RouterLabels {
            router: router.name.clone(),
        };

        let success_count = state.metrics.get_scrape_success_count(&router_label);
        let error_count = state.metrics.get_scrape_error_count(&router_label);

        let consecutive_errors = if let Some((errors, _)) = state
            .pool
            .get_connection_state(&router.address, &router.username, None)
            .await
        {
            errors
        } else {
            0
        };

        let status = classify_router_status(success_count, error_count, consecutive_errors);
        if matches!(status, RouterStatus::Degraded) {
            all_healthy = false;
        }

        routers_health.push(RouterHealth {
            name: router.name.clone(),
            status: status.as_str().to_string(),
            consecutive_errors,
            has_successful_scrape: success_count > 0,
        });
    }

    let overall_status = if all_healthy { "healthy" } else { "degraded" };
    let status_code = if all_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status_code,
        HealthResponse {
            status: overall_status.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            routers: routers_health,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_router_status() {
        assert!(matches!(
            classify_router_status(1, 0, 0),
            RouterStatus::Healthy
        ));
        assert!(matches!(
            classify_router_status(0, 1, 0),
            RouterStatus::Degraded
        ));
        assert!(matches!(
            classify_router_status(0, 0, HEALTHY_MAX_CONSECUTIVE_ERRORS),
            RouterStatus::Degraded
        ));
        assert!(matches!(
            classify_router_status(0, 0, 0),
            RouterStatus::Unknown
        ));
    }
}
