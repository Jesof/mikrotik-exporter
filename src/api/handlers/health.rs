use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

/// Структура ответа health check endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// GET /health
///
/// Простой health check endpoint для мониторинга состояния сервиса.
/// Возвращает статус "ok" и версию приложения.
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
