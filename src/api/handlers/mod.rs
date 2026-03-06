// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! HTTP endpoint handlers for `MikroTik` Exporter
//!
//! # Endpoints
//!
//! This module implements the HTTP API handlers for the exporter:
//!
//! - **`/health`** (`health_check`): Health check endpoint with router availability
//!   - Returns HTTP 200 when all routers are healthy
//!   - Returns HTTP 503 when any router is degraded
//!   - Provides detailed status for each router including:
//!     - Current status (healthy/degraded)
//!     - Consecutive connection errors
//!     - Scrape success history
//!
//! - **`/metrics`** (`metrics_handler`): Prometheus metrics endpoint
//!   - Returns metrics in `OpenMetrics` format
//!   - Content-Type: `application/openmetrics-text; version=1.0.0`
//!   - Encodes all collected metrics from the registry
//!   - Handles encoding errors gracefully with 500 response
//!
//! ## Implementation Details
//!
//! - Handlers use Axum's extractor system for state access
//! - State is shared via `Arc<AppState>` for thread safety
//! - Health check queries both metrics registry and connection pool
//! - Metrics encoding is asynchronous to avoid blocking
//!
//! ## Response Codes
//!
//! ### `/health`
//! - `200 OK`: All routers healthy
//! - `503 Service Unavailable`: One or more routers degraded
//!
//! ### `/metrics`
//! - `200 OK`: Metrics successfully encoded
//! - `500 Internal Server Error`: Encoding failed

mod health;
mod metrics;

pub use health::health_check;
pub use metrics::metrics_handler;
