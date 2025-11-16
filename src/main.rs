// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Main entry point for MikroTik Exporter
//!
//! Initializes configuration, logging, metrics collection, and HTTP API.
//! - Loads environment variables
//! - Sets up logging
//! - Reads router configuration
//! - Starts background metrics collection
//! - Waits for shutdown signal
//! - Runs HTTP server for Prometheus

use mikrotik_exporter::{api, collector, config::Config, error::Result, metrics};

use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file
    dotenvy::dotenv().ok();

    // Initialize logging
    setup_tracing();

    // Initialize configuration before creating Tokio runtime
    let config = Config::from_env();

    // Log configuration info
    tracing::info!(
        "Loaded configuration for {} router(s)",
        config.routers.len()
    );
    for router in &config.routers {
        tracing::info!("  - Router '{}' at {}", router.name, router.address);
    }

    // Create metrics registry
    let metrics = metrics::MetricsRegistry::new();

    // Create application state
    let state = Arc::new(api::AppState {
        config: config.clone(),
        metrics: metrics.clone(),
    });

    // Graceful shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Wait for Ctrl+C
    tokio::spawn({
        let shutdown_tx = shutdown_tx.clone();
        async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("Shutdown signal received");
                let _ = shutdown_tx.send(true);
            }
        }
    });

    // Start periodic background metrics collection
    collector::start_collection_loop(shutdown_rx.clone(), Arc::new(config.clone()), metrics);

    // Create the router
    let app = api::create_router(state);

    let addr: SocketAddr = config.server_addr.parse().map_err(|e| {
        tracing::error!("Invalid server address: {}", e);
        e
    })?;

    // Setup address for listening
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        tracing::error!("Failed to bind address: {}", e);
        e
    })?;

    tracing::info!("MikroTik Exporter starting on {}", addr);
    tracing::info!("Endpoints:");
    tracing::info!("  - GET /health  - Health check");
    tracing::info!("  - GET /metrics - Prometheus metrics");

    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.clone().changed().await;
            tracing::info!("HTTP server shutting down");
        })
        .await
        .map_err(|e| {
            tracing::error!("Server error: {}", e);
            e
        })?;

    Ok(())
}

fn setup_tracing() {
    // Use EnvFilter::from_default_env() for proper RUST_LOG handling
    // If RUST_LOG is not set, use "info" by default
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
