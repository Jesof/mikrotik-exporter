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
    async fn test_metrics_handler_returns_ok() {
        let config = Config {
            server_addr: "127.0.0.1:9090".to_string(),
            routers: vec![RouterConfig {
                name: "test-router".to_string(),
                address: "192.168.1.1".to_string(),
                username: "admin".to_string(),
                password: "password".to_string(),
            }],
            collection_interval_secs: 30,
        };

        let metrics = MetricsRegistry::new();
        let app_state = Arc::new(AppState { config, metrics });

        let response = metrics_handler(State(app_state)).await;
        let status = response.status();

        assert_eq!(status, StatusCode::OK);
    }
}
