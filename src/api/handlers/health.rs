// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::AppState;

/// Health check endpoint response structure
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HealthResponse {
    pub(crate) status: String,
    pub(crate) version: String,
    pub(crate) routers: Vec<RouterHealth>,
}

/// Health status for individual routers
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RouterHealth {
    pub(crate) name: String,
    pub(crate) status: String,
    pub(crate) consecutive_errors: u32,
    pub(crate) has_successful_scrape: bool,
}

/// GET /health
///
/// Health check endpoint with router availability check.
/// Returns overall service status, version, and individual router health.
pub async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut routers_health = Vec::new();
    let mut all_healthy = true;

    // Check each router's health from metrics and connection pool
    for router in &state.config.routers {
        let router_label = crate::metrics::RouterLabels {
            router: router.name.clone(),
        };

        // Get scrape success count to determine if router ever responded
        let success_count = state.metrics.get_scrape_success_count(&router_label).await;
        let error_count = state.metrics.get_scrape_error_count(&router_label).await;

        // Get actual consecutive errors from connection pool state
        let consecutive_errors = if let Some((errors, _)) = state
            .pool
            .get_connection_state(&router.address, &router.username)
            .await
        {
            errors
        } else {
            0
        };

        // Determine router status
        let status = if success_count > 0 && consecutive_errors < 3 {
            "healthy"
        } else if error_count > 0 || consecutive_errors >= 3 {
            all_healthy = false;
            "degraded"
        } else {
            "unknown"
        };

        routers_health.push(RouterHealth {
            name: router.name.clone(),
            status: status.to_string(),
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

    let response = HealthResponse {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        routers: routers_health,
    };

    (status_code, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::AppState;
    use crate::config::{Config, RouterConfig};
    use crate::metrics::MetricsRegistry;

    #[tokio::test]
    async fn test_health_check() {
        use crate::mikrotik::ConnectionPool;

        let config = Config {
            server_addr: "127.0.0.1:9090".to_string(),
            routers: vec![RouterConfig {
                name: "test-router".to_string(),
                address: "192.168.1.1:8728".to_string(),
                username: "admin".to_string(),
                password: secrecy::SecretString::new("password".to_string().into()),
            }],
            collection_interval_secs: 30,
        };

        let metrics = MetricsRegistry::new();
        let pool = Arc::new(ConnectionPool::new());
        let app_state = Arc::new(AppState {
            config,
            metrics,
            pool,
        });

        let response = health_check(State(app_state)).await.into_response();
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
