// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use mikrotik_exporter::{
    AppError, AppState, Config, ConnectionPool, MetricsRegistry, Result,
    run_startup_connectivity_tests, start_collection_loop,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> Result<()> {
    if version_requested(std::env::args_os().skip(1))? {
        println!("mikrotik-exporter {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    dotenvy::dotenv().ok();
    setup_tracing();
    let config = Config::from_env()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(config))
}

fn version_requested(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<bool> {
    let mut args = args.into_iter();
    match (args.next(), args.next()) {
        (None, None) => Ok(false),
        (Some(arg), None) if arg == "--version" || arg == "-V" => Ok(true),
        _ => Err(AppError::Config(
            "Unsupported arguments; use --version or configure via environment variables".into(),
        )),
    }
}

#[derive(Debug)]
enum TaskExit {
    Initialized,
    Http,
}

async fn run(config: Config) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(&config.server_addr).await?;
    tracing::info!(address = %listener.local_addr()?, routers = config.routers.len(), "Starting exporter");
    let config = Arc::new(config);
    let metrics = MetricsRegistry::new();
    let pool = Arc::new(ConnectionPool::new());
    let state = Arc::new(AppState {
        config: (*config).clone(),
        metrics: metrics.clone(),
        pool: pool.clone(),
    });
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = watch::channel(false);
    let app = state.router_with_readiness(ready_rx);
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
            .await?;
        Ok(TaskExit::Http)
    });
    let startup_config = config.clone();
    tasks.spawn(async move {
        run_startup_connectivity_tests(&startup_config).await?;
        Ok(TaskExit::Initialized)
    });
    let signal = shutdown_signal();
    tokio::pin!(signal);
    let mut collector: Option<tokio::task::JoinHandle<Result<()>>> = None;
    let outcome = loop {
        tokio::select! {
            result = &mut signal => break result,
            result = async {
                match collector.as_mut() {
                    Some(handle) => handle.await,
                    None => std::future::pending().await,
                }
            } => {
                collector = None;
                break match result {
                    Ok(Err(error)) => Err(error),
                    other => Err(AppError::Io(std::io::Error::other(format!("Collector stopped unexpectedly: {other:?}")))),
                };
            }
            result = tasks.join_next() => {
                match result {
                    Some(Ok(Ok(TaskExit::Initialized))) => {
                        collector = Some(start_collection_loop(shutdown_tx.subscribe(), config.clone(), metrics.clone(), pool.clone()));
                        ready_tx.send_replace(true);
                    }
                    Some(Ok(Err(error))) => break Err(error),
                    other => break Err(AppError::Io(std::io::Error::other(format!("Runtime task stopped unexpectedly: {other:?}")))),
                }
            }
        }
    };
    ready_tx.send_replace(false);
    shutdown_tx.send_replace(true);
    if let Some(mut handle) = collector
        && tokio::time::timeout(Duration::from_secs(5), &mut handle)
            .await
            .is_err()
    {
        handle.abort();
        let _ = handle.await;
    }
    drain_tasks(&mut tasks).await;
    outcome
}

async fn drain_tasks(tasks: &mut JoinSet<Result<TaskExit>>) {
    if tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(result) = tasks.join_next().await {
            if !matches!(result, Ok(Ok(_))) {
                tracing::error!(?result, "Task failed during shutdown");
            }
        }
    })
    .await
    .is_err()
    {
        tasks.shutdown().await;
    }
}

async fn wait_for_shutdown(mut rx: watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() || rx.changed().await.is_err() {
            return;
        }
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn setup_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_arguments() {
        assert!(!version_requested([]).unwrap());
        assert!(version_requested(["--version".into()]).unwrap());
        assert!(version_requested(["-V".into()]).unwrap());
        assert!(version_requested(["--unknown".into()]).is_err());
        assert!(version_requested(["--version".into(), "extra".into()]).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn test_shutdown_already_signalled_and_closed_channel() {
        for value in [true, false] {
            let (tx, rx) = watch::channel(value);
            drop(tx);
            tokio::time::timeout(Duration::from_secs(1), wait_for_shutdown(rx))
                .await
                .unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_shutdown_aborts_and_joins_stuck_tasks() {
        let mut tasks = JoinSet::new();
        tasks.spawn(std::future::pending::<Result<TaskExit>>());
        drain_tasks(&mut tasks).await;
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn test_startup_failure_is_observed_and_http_server_stops() {
        let config = Config {
            server_addr: "127.0.0.1:0".into(),
            strict_startup_mode: true,
            ..Config::default()
        };
        let result = tokio::time::timeout(Duration::from_secs(1), run(config))
            .await
            .unwrap();
        assert!(matches!(result, Err(AppError::Config(_))));
    }
}
