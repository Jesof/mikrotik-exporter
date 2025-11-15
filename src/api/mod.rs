//! HTTP API module for MikroTik Exporter
//!
//! Provides REST API endpoints for health checks and Prometheus metrics export.
//!
//! # Endpoints
//! - `GET /health` — health check
//! - `GET /metrics` — Prometheus metrics

pub mod handlers;

use axum::{Router, routing::get};
use std::sync::Arc;

use crate::config::Config;
use crate::metrics::MetricsRegistry;

/// Application state shared with endpoints
pub struct AppState {
    pub config: Config,
    pub metrics: MetricsRegistry,
}

/// Creates the main Axum router with all endpoints
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/metrics", get(handlers::metrics_handler))
        .with_state(state)
}
