// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use mikrotik_exporter::{
    AppState, Config, ConfigError, ConnectionPool, InterfaceStats, MetricsRegistry, RouterLabels,
    RouterMetrics, SystemResource, run_startup_connectivity_tests, start_collection_loop,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tower::ServiceExt;

/// Extracts the environment variable key from a typed config error, if any.
fn config_error_key(error: &ConfigError) -> Option<String> {
    use mikrotik_exporter::ConfigError as E;
    match error {
        E::InvalidRoutersJson { key, .. }
        | E::InvalidJson { key }
        | E::InvalidValue { key }
        | E::InvalidUnicode { key }
        | E::OutOfRange { key, .. } => Some(key.clone()),
        E::InvalidServerAddr => Some("SERVER_ADDR".into()),
        E::StrictRequiresConnectivityTest | E::StrictRequiresRouter => {
            Some("STRICT_STARTUP_MODE".into())
        }
        E::DuplicateRouterName { .. }
        | E::StrictUnreachable { .. }
        | E::UnsupportedArguments
        | E::Router(_)
        | E::Tls(_) => None,
    }
}

fn config() -> Config {
    Config::from_lookup(|key| Ok((key == "ROUTEROS_ADDRESS").then(|| "127.0.0.1:8728".into())))
        .unwrap()
}

#[tokio::test]
async fn test_process_probes_are_independent_of_router_health() {
    let state = Arc::new(AppState {
        config: config(),
        metrics: MetricsRegistry::new(),
        pool: Arc::new(ConnectionPool::new()),
    });
    let (ready_tx, ready_rx) = watch::channel(false);
    let app = state.router_with_readiness(ready_rx);
    for (path, expected) in [
        ("/live", StatusCode::OK),
        ("/ready", StatusCode::SERVICE_UNAVAILABLE),
        ("/health", StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{path}");
    }
    ready_tx.send_replace(true);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    ready_tx.send_replace(false);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_metrics_are_retrievable_through_public_http_api() {
    let metrics = MetricsRegistry::new();
    let labels = RouterLabels {
        router: "default".into(),
    };
    metrics.initialize_router_metrics(&labels);
    let snapshot = RouterMetrics {
        router_name: "default".into(),
        system: SystemResource {
            uptime: "1d".into(),
            cpu_load: 42,
            free_memory: 512,
            total_memory: 1024,
            version: "7.10".into(),
            board_name: "test".into(),
        },
        interfaces: vec![InterfaceStats {
            id: "*1".into(),
            name: "ether1".into(),
            running: true,
            rx_bytes: 1000,
            tx_bytes: 2000,
            ..InterfaceStats::default()
        }],
        ..RouterMetrics::default()
    };
    metrics.update_metrics(&snapshot);
    metrics.record_scrape_success(&labels);
    metrics.record_scrape_error(&labels);
    metrics.record_collection_cycle_duration(1.234);
    metrics.update_pool_stats(10, 5);
    assert_eq!(metrics.get_scrape_success_count(&labels), 1);
    assert_eq!(metrics.get_scrape_error_count(&labels), 1);
    let state = Arc::new(AppState {
        config: config(),
        metrics,
        pool: Arc::new(ConnectionPool::new()),
    });
    let response = mikrotik_exporter::create_router(state)
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let text = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(text.contains("mikrotik_collection_cycle_duration_seconds 1.234"));
    assert!(text.contains("mikrotik_connection_pool_size 10"));
    assert!(text.contains("mikrotik_connection_pool_active 5"));
    assert!(
        text.contains("mikrotik_system_cpu_load_ratio{router=\"default\"} 0.42"),
        "{text}"
    );
}

#[tokio::test(start_paused = true)]
async fn test_collector_shutdown_cancels_inflight_router_io() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let config =
        Config::from_lookup(|key| Ok((key == "ROUTEROS_ADDRESS").then(|| address.clone())))
            .unwrap();
    let (tx, rx) = watch::channel(false);
    let handle = start_collection_loop(
        rx,
        Arc::new(config),
        MetricsRegistry::new(),
        Arc::new(ConnectionPool::new()),
    );
    let (_socket, _) = listener.accept().await.unwrap();
    tx.send_replace(true);
    // Pause + advance past the schedule geometry so shutdown and the abort
    // drain resolve deterministically regardless of runner load.
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[test]
fn test_cli_version_and_invalid_arguments_without_configuration() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mikrotik-exporter"))
        .arg("--version")
        .env_clear()
        .env("COLLECTION_INTERVAL_SECONDS", "invalid")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("mikrotik-exporter {}", env!("CARGO_PKG_VERSION"))
    );
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mikrotik-exporter"))
        .arg("--unsupported")
        .env_clear()
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Unsupported arguments")
    );
}

#[tokio::test]
#[ignore = "requires explicitly configured real RouterOS devices"]
async fn test_real_router_connectivity() {
    let mut values = std::collections::HashMap::new();
    if let Ok(entries) = dotenvy::dotenv_iter() {
        for entry in entries {
            let (key, value) = entry.unwrap();
            values.insert(key, value);
        }
    }
    values.extend(std::env::vars());
    let mut config = Config::from_lookup(|key| Ok(values.get(key).cloned())).unwrap();
    assert!(
        !config.routers.is_empty(),
        "Explicit real-device test requires router configuration"
    );
    config.startup_connectivity_test = true;
    config.strict_startup_mode = true;
    run_startup_connectivity_tests(&config).await.unwrap();
}

// Temporary, local-only audit: never print values or propagate private errors.
#[test]
#[ignore = "explicit local dotenv audit; no device access"]
fn test_local_env_audit() -> Result<(), &'static str> {
    let before = std::fs::read(".env").map_err(|_| "dotenv read failed")?;
    let entries = dotenvy::dotenv_iter().map_err(|_| "dotenv open failed")?;
    let mut values = std::collections::HashMap::new();
    let mut duplicates = 0;
    for entry in entries {
        let (key, value) = entry.map_err(|_| "dotenv syntax invalid")?;
        duplicates += usize::from(values.insert(key, value).is_some());
    }
    let keys = [
        "SERVER_ADDR",
        "ROUTERS_CONFIG",
        "COLLECTION_INTERVAL_SECONDS",
        "GAP_RESET_THRESHOLD_SECONDS",
        "STARTUP_CONNECTIVITY_TEST",
        "STARTUP_CONNECTIVITY_TIMEOUT_SECS",
        "STRICT_STARTUP_MODE",
        "ROUTEROS_ADDRESS",
        "ROUTEROS_USERNAME",
        "ROUTEROS_PASSWORD",
        "ROUTEROS_TLS",
        "RUST_LOG",
        "COLLECTION_INTERVAL_SECS",
        "GAP_RESET_THRESHOLD_SECS",
        "COLLECTION_INTERVAL",
        "GAP_RESET_THRESHOLD",
    ];
    let recognized: Vec<_> = keys
        .into_iter()
        .filter(|key| values.contains_key(*key))
        .collect();
    println!(
        "env recognized_keys={recognized:?} unknown_keys={} duplicate_keys={duplicates}",
        values.len() - recognized.len()
    );
    let config = Config::from_lookup(|key| Ok(values.get(key).cloned()));
    match &config {
        Ok(config) => println!(
            "env validation=ok routers={} tls={} plaintext={}",
            config.routers.len(),
            config.routers.iter().filter(|r| r.tls.is_some()).count(),
            config.routers.iter().filter(|r| r.tls.is_none()).count()
        ),
        Err(mikrotik_exporter::AppError::Config(error)) => {
            let error_key = config_error_key(error);
            let fields: Vec<_> = keys
                .into_iter()
                .filter(|key| {
                    error_key
                        .as_ref()
                        .is_none_or(|error_key| error_key.contains(*key))
                })
                .collect();
            println!("env validation=failed fields={fields:?} {error}");
        }
        Err(_) => println!("env validation=failed"),
    }
    let after = std::fs::read(".env").map_err(|_| "dotenv reread failed")?;
    let unchanged = md5::compute(&before) == md5::compute(&after);
    println!("env unchanged={unchanged}");
    if !unchanged {
        return Err("dotenv changed");
    }
    config
        .map(|_| ())
        .map_err(|_| "config validation failed (redacted)")
}
