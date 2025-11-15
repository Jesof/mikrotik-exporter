mod api;
mod config;
mod error;
mod metrics;
mod mikrotik;

use std::net::SocketAddr;
use std::sync::Arc;

use error::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use config::Config;
use metrics::MetricsRegistry;
use mikrotik::MikroTikClient;
use tokio::sync::watch;
use tokio::task::JoinHandle;

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
    let metrics = MetricsRegistry::new();

    // Создаём состояние приложения
    let state = Arc::new(api::handlers::AppState {
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
    start_collection_loop(shutdown_rx.clone(), state.clone());

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

fn start_collection_loop(
    mut shutdown_rx: watch::Receiver<bool>,
    state: Arc<api::handlers::AppState>,
) -> JoinHandle<()> {
    let interval = state.config.collection_interval_secs;
    tracing::info!("Starting background collection loop every {}s", interval);

    // Create shared connection pool for all routers
    let pool = Arc::new(mikrotik::ConnectionPool::new());

    // Start cleanup task for expired connections
    let cleanup_pool = pool.clone();
    let mut cleanup_shutdown = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut cleanup_ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = cleanup_ticker.tick() => {
                    cleanup_pool.cleanup().await;
                },
                _ = cleanup_shutdown.changed() => {
                    if *cleanup_shutdown.borrow() {
                        tracing::debug!("Stopping connection pool cleanup");
                        break;
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval));
        loop {
            tokio::select! {
                _ = ticker.tick() => {},
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Stopping collection loop");
                        break;
                    }
                }
            }
            for router in &state.config.routers {
                let client = MikroTikClient::with_pool(router.clone(), pool.clone());
                let metrics_ref = state.metrics.clone();
                let router_name = router.name.clone();
                let router_label = metrics::RouterLabels {
                    router: router_name.clone(),
                };
                let pool_ref = pool.clone();
                let router_config = router.clone();
                tokio::spawn(async move {
                    let start = std::time::Instant::now();
                    match client.collect_metrics().await {
                        Ok(m) => {
                            let duration = start.elapsed().as_secs_f64();
                            metrics_ref.update_metrics(&m).await;
                            metrics_ref.record_scrape_success(&router_label);
                            metrics_ref.record_scrape_duration(&router_label, duration);

                            // Update connection error count
                            if let Some((errors, _)) = pool_ref
                                .get_connection_state(
                                    &router_config.address,
                                    &router_config.username,
                                )
                                .await
                            {
                                metrics_ref.update_connection_errors(&router_label, errors);
                            }

                            tracing::debug!(
                                "Collected metrics for router {} in {:.3}s",
                                router_name,
                                duration
                            );
                        }
                        Err(e) => {
                            let duration = start.elapsed().as_secs_f64();
                            metrics_ref.record_scrape_error(&router_label);
                            metrics_ref.record_scrape_duration(&router_label, duration);

                            // Update connection error count
                            if let Some((errors, _)) = pool_ref
                                .get_connection_state(
                                    &router_config.address,
                                    &router_config.username,
                                )
                                .await
                            {
                                metrics_ref.update_connection_errors(&router_label, errors);
                            }

                            tracing::warn!(
                                "Failed to collect metrics for {} in {:.3}s: {}",
                                router_name,
                                duration,
                                e
                            );
                        }
                    }
                });
            }

            // Update pool statistics after all routers processed
            let (total, active) = pool.get_pool_stats().await;
            state.metrics.update_pool_stats(total, active);
        }
    })
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
