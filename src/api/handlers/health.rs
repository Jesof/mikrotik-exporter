use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

/// Health check endpoint response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// GET /health
///
/// Simple health check endpoint for monitoring service status.
/// Returns "ok" status and application version.
pub async fn health_check() -> impl IntoResponse {
    let response = HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    (StatusCode::OK, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
