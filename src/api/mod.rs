//! HTTP API module
//!
//! Provides REST API endpoints for health checks and Prometheus metrics.

pub mod handlers;

use axum::{Router, routing::get};
use std::sync::Arc;

/// Создаёт основной router приложения со всеми endpoint'ами
pub fn create_router(state: Arc<handlers::AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/metrics", get(handlers::metrics_handler))
        .with_state(state)
}
