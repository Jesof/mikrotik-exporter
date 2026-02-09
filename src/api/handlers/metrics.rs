// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::api::AppState;

pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> Response {
    tracing::debug!("/metrics encode cached scrape");
    match state.metrics.encode_metrics().await {
        Ok(metrics_text) => (
            StatusCode::OK,
            [("Content-Type", "text/plain; version=0.0.4")],
            metrics_text,
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to encode metrics: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to encode metrics: {e}"),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RouterConfig};
    use crate::metrics::MetricsRegistry;

    #[tokio::test]
    async fn test_metrics_endpoint() {
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

        let response = metrics_handler(State(app_state)).await;
        let status = response.status();

        assert_eq!(status, StatusCode::OK);
    }
}
