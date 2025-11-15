//! HTTP API module
//!
//! Provides REST API endpoints for health checks and Prometheus metrics.
//!
//! # Endpoints
//!
//! - `GET /health` - Health check endpoint
//! - `GET /metrics` - Prometheus metrics endpoint

pub mod handlers;

use axum::{Router, routing::get};
use std::sync::Arc;

use crate::config::Config;
use crate::metrics::MetricsRegistry;

/// Shared application state
pub struct AppState {
    pub config: Config,
    pub metrics: MetricsRegistry,
}

/// Создаёт основной router приложения со всеми endpoint'ами
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/metrics", get(handlers::metrics_handler))
        .with_state(state)
}
