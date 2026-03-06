// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::api::AppState;
use crate::metrics::RouterLabels;

const HEALTHY_MAX_CONSECUTIVE_ERRORS: u32 = 3;
const HEALTH_STALE_AFTER_COLLECTIONS: u64 = 3;

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
}

impl RouterStatus {
    fn as_str(self) -> &'static str {
        match self {
            RouterStatus::Healthy => "healthy",
            RouterStatus::Degraded => "degraded",
        }
    }
}

fn classify_router_status(
    success_count: u64,
    consecutive_errors: u32,
    last_success_age: Option<Duration>,
    stale_after: Duration,
) -> RouterStatus {
    if success_count > 0
        && consecutive_errors < HEALTHY_MAX_CONSECUTIVE_ERRORS
        && last_success_age.is_some_and(|age| age <= stale_after)
    {
        RouterStatus::Healthy
    } else {
        RouterStatus::Degraded
    }
}

fn health_stale_after(state: &AppState) -> Duration {
    Duration::from_secs(
        state
            .config
            .collection_interval_secs
            .saturating_mul(HEALTH_STALE_AFTER_COLLECTIONS)
            .max(state.config.gap_reset_threshold_secs)
            .max(1),
    )
}

pub(crate) async fn build_health_response(state: &AppState) -> (StatusCode, HealthResponse) {
    if state.config.routers.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            HealthResponse {
                status: "degraded".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                routers: Vec::new(),
            },
        );
    }

    let mut routers_health = Vec::new();
    let mut all_healthy = true;
    let stale_after = health_stale_after(state);

    for router in &state.config.routers {
        let router_label = RouterLabels {
            router: router.name.clone(),
        };

        let success_count = state.metrics.get_scrape_success_count(&router_label);
        let last_success_age = state.metrics.get_last_scrape_success_age(&router.name);

        let consecutive_errors = if let Some((errors, _)) = state
            .pool
            .get_connection_state(&router.address, &router.username, None)
            .await
        {
            errors
        } else {
            0
        };

        let status = classify_router_status(
            success_count,
            consecutive_errors,
            last_success_age,
            stale_after,
        );
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
            classify_router_status(1, 0, Some(Duration::from_secs(1)), Duration::from_secs(5)),
            RouterStatus::Healthy
        ));
        assert!(matches!(
            classify_router_status(0, 0, None, Duration::from_secs(5)),
            RouterStatus::Degraded
        ));
        assert!(matches!(
            classify_router_status(
                1,
                HEALTHY_MAX_CONSECUTIVE_ERRORS,
                Some(Duration::from_secs(1)),
                Duration::from_secs(5)
            ),
            RouterStatus::Degraded
        ));
        assert!(matches!(
            classify_router_status(1, 0, Some(Duration::from_secs(10)), Duration::from_secs(5)),
            RouterStatus::Degraded
        ));
    }
}
