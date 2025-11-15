//! HTTP API module
//!
//! Provides REST API endpoints for health checks and Prometheus metrics.

pub mod handlers;
pub mod state;

use axum::{Router, routing::get};
use std::sync::Arc;

pub use state::AppState;

/// Создаёт основной router приложения со всеми endpoint'ами
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/metrics", get(handlers::metrics_handler))
        .with_state(state)
}
