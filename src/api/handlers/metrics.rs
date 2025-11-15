use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::config::Config;
use crate::metrics::MetricsRegistry;

pub struct AppState {
    pub config: Config,
    pub metrics: MetricsRegistry,
}

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
                format!("Failed to encode metrics: {}", e),
            )
                .into_response()
        }
    }
}
