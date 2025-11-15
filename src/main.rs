use mikrotik_exporter::*;

use std::net::SocketAddr;
use std::sync::Arc;

use error::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<()> {
    // Загружаем .env файл
    dotenvy::dotenv().ok();

    // Инициализация логирования
    setup_tracing();

    // Инициализируем конфигурацию до создания токио рантайма
    let config = Config::from_env();

    // Логируем информацию о конфигурации
    tracing::info!(
        "Loaded configuration for {} router(s)",
        config.routers.len()
    );
    for router in &config.routers {
        tracing::info!("  - Router '{}' at {}", router.name, router.address);
    }

    // Создаём реестр метрик
    let metrics = metrics::MetricsRegistry::new();

    // Создаём состояние приложения
    let state = Arc::new(api::AppState {
        config: config.clone(),
        metrics,
    });

    // Канал завершения (graceful shutdown)
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Ожидание Ctrl+C
    tokio::spawn({
        let shutdown_tx = shutdown_tx.clone();
        async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("Shutdown signal received");
                let _ = shutdown_tx.send(true);
            }
        }
    });

    // Запускаем периодический сбор метрик в фоне
    collector::start_collection_loop(shutdown_rx.clone(), state.clone());

    // Создание router
    let app = api::create_router(state);

    let addr: SocketAddr = config.server_addr.parse().map_err(|e| {
        tracing::error!("Invalid server address: {}", e);
        e
    })?;

    // Настройка адреса для прослушивания
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        tracing::error!("Failed to bind address: {}", e);
        e
    })?;

    tracing::info!("MikroTik Exporter starting on {}", addr);
    tracing::info!("Endpoints:");
    tracing::info!("  - GET /health  - Health check");
    tracing::info!("  - GET /metrics - Prometheus metrics");

    // Запуск сервера с graceful shutdown
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
    // Используем EnvFilter::from_default_env() для правильной обработки RUST_LOG
    // Если RUST_LOG не установлена, используем "info" по умолчанию
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
