// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use axum::{Json, extract::State, response::IntoResponse};
use std::sync::Arc;

use crate::api::AppState;
use crate::api::health::build_health_response;

/// GET /health
///
/// Health check endpoint with router availability check.
/// Returns overall service status, version, and individual router health.
pub async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (status_code, response) = build_health_response(&state).await;
    (status_code, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::AppState;
    use crate::config::{Config, RouterConfig};
    use crate::metrics::MetricsRegistry;
    use axum::{http::StatusCode, response::IntoResponse};

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
            gap_reset_threshold_secs: 60,
            startup_connectivity_test: false,
            startup_connectivity_timeout_secs: 10,
            strict_startup_mode: false,
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
