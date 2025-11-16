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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RouterConfig};
    use crate::metrics::MetricsRegistry;

    #[test]
    fn test_create_router() {
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

        let _router = create_router(app_state);
        // If we get here without panicking, the router was created successfully
    }

    #[test]
    fn test_app_state_creation() {
        let config = Config::default();
        let metrics = MetricsRegistry::new();

        let state = AppState { config, metrics };

        assert_eq!(state.config.server_addr, "0.0.0.0:9090");
        assert_eq!(state.config.collection_interval_secs, 30);
    }
}
