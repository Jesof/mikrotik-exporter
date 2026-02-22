// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mikrotik_exporter::{
    AppState, Config, ConnectionPool, InterfaceStats, MetricsRegistry, RouterConfig, RouterLabels,
    RouterMetrics, SystemResource, create_router,
};
use std::sync::Arc;
use tower::ServiceExt;

fn make_state(routers: Vec<RouterConfig>) -> Arc<AppState> {
    let config = Config {
        server_addr: "127.0.0.1:9090".to_string(),
        routers,
        collection_interval_secs: 30,
        startup_connectivity_test: false,
        startup_connectivity_timeout_secs: 10,
        strict_startup_mode: false,
    };
    let metrics = MetricsRegistry::new();
    let pool = Arc::new(ConnectionPool::new());
    Arc::new(AppState {
        config,
        metrics,
        pool,
    })
}

fn test_router(name: &str) -> RouterConfig {
    RouterConfig {
        name: name.to_string(),
        address: "192.168.1.1:8728".to_string(),
        username: "admin".to_string(),
        password: secrecy::SecretString::new("password".to_string().into()),
    }
}

// --- /metrics endpoint ---

#[tokio::test]
async fn metrics_returns_200_with_openmetrics_content_type() {
    let state = make_state(vec![test_router("r1")]);
    let app = create_router(state);

    let resp = app
        .oneshot(Request::get("/metrics").body(String::new()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.contains("openmetrics-text"),
        "Expected OpenMetrics content-type, got: {ct}"
    );
}

#[tokio::test]
async fn metrics_contains_registered_metric_names() {
    let state = make_state(vec![test_router("r1")]);
    let app = create_router(state);

    let resp = app
        .oneshot(Request::get("/metrics").body(String::new()).unwrap())
        .await
        .unwrap();

    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    assert!(body.contains("mikrotik_connection_pool_size"));
    assert!(body.contains("mikrotik_connection_pool_active"));
    assert!(body.contains("mikrotik_collection_cycle_duration_milliseconds"));
}

#[tokio::test]
async fn metrics_contains_router_data_after_update() {
    let state = make_state(vec![test_router("myrouter")]);

    let iface = InterfaceStats {
        name: "ether1".to_string(),
        comment: "WAN".to_string(),
        rx_bytes: 1000,
        tx_bytes: 2000,
        rx_packets: 10,
        tx_packets: 20,
        rx_errors: 1,
        tx_errors: 2,
        running: true,
    };

    let system = SystemResource {
        uptime: "1d".to_string(),
        cpu_load: 42,
        free_memory: 512_000_000,
        total_memory: 1_024_000_000,
        version: "7.10".to_string(),
        board_name: "RB750Gr3".to_string(),
    };
    let metrics = RouterMetrics {
        router_name: "myrouter".to_string(),
        interfaces: vec![iface],
        system,
        connection_tracking: Vec::new(),
        wireguard_peers: vec![],
        certificate_stats: vec![],
        firewall_rules: vec![mikrotik_exporter::FirewallRuleStats {
            id: "*1".to_string(),
            comment: "Drop invalid".to_string(),
            chain: "forward".to_string(),
            action: "accept".to_string(),
            bytes: 1024,
            packets: 5,
            ip_version: "ipv4".to_string(),
            section: "filter".to_string(),
        }],
    };
    state.metrics.update_metrics(&metrics).await;

    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/metrics").body(String::new()).unwrap())
        .await
        .unwrap();

    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    assert!(body.contains("router=\"myrouter\""));
    assert!(body.contains("interface=\"ether1\""));
    assert!(body.contains("mikrotik_system_cpu_load"));
}

#[tokio::test]
async fn metrics_correctly_calculates_interface_counters() {
    let state = make_state(vec![test_router("router1")]);

    // First update with initial values
    let iface = InterfaceStats {
        name: "ether1".to_string(),
        comment: "WAN".to_string(),
        rx_bytes: 1000,
        tx_bytes: 2000,
        rx_packets: 10,
        tx_packets: 20,
        rx_errors: 1,
        tx_errors: 2,
        running: true,
    };
    let system = SystemResource {
        uptime: "1d".to_string(),
        cpu_load: 42,
        free_memory: 512_000_000,
        total_memory: 1_024_000_000,
        version: "7.10".to_string(),
        board_name: "RB750Gr3".to_string(),
    };
    let metrics1 = RouterMetrics {
        router_name: "router1".to_string(),
        interfaces: vec![iface],
        system: system.clone(),
        connection_tracking: Vec::new(),
        wireguard_peers: vec![],
        certificate_stats: vec![],
        firewall_rules: vec![mikrotik_exporter::FirewallRuleStats {
            id: "*1".to_string(),
            comment: "Drop invalid".to_string(),
            chain: "forward".to_string(),
            action: "accept".to_string(),
            bytes: 1024,
            packets: 5,
            ip_version: "ipv4".to_string(),
            section: "filter".to_string(),
        }],
    };
    state.metrics.update_metrics(&metrics1).await;

    // Second update with incremented values
    let iface2 = InterfaceStats {
        name: "ether1".to_string(),
        comment: "WAN".to_string(),
        rx_bytes: 3000, // +2000
        tx_bytes: 5000, // +3000
        rx_packets: 25, // +15
        tx_packets: 35, // +15
        rx_errors: 1,   // +0
        tx_errors: 4,   // +2
        running: true,
    };
    let metrics2 = RouterMetrics {
        router_name: "router1".to_string(),
        interfaces: vec![iface2],
        system,
        connection_tracking: Vec::new(),
        wireguard_peers: vec![],
        certificate_stats: vec![],
        firewall_rules: vec![mikrotik_exporter::FirewallRuleStats {
            id: "*1".to_string(),
            comment: "Drop invalid".to_string(),
            chain: "forward".to_string(),
            action: "accept".to_string(),
            bytes: 1024,
            packets: 5,
            ip_version: "ipv4".to_string(),
            section: "filter".to_string(),
        }],
    };
    state.metrics.update_metrics(&metrics2).await;

    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/metrics").body(String::new()).unwrap())
        .await
        .unwrap();

    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    // Check that counter starts with initial values and increments by delta
    // First update: rx_bytes=1000, tx_bytes=2000, rx_packets=10, tx_packets=20
    // Second update: delta rx=2000, delta tx=3000, delta rx_pkts=15, delta tx_pkts=15
    // Final counter: rx=3000, tx=5000, rx_pkts=25, tx_pkts=35
    assert!(body.contains(
        "mikrotik_interface_rx_bytes_total{router=\"router1\",interface=\"ether1\",comment=\"WAN\"} 3000"
    ));
    assert!(body.contains(
        "mikrotik_interface_tx_bytes_total{router=\"router1\",interface=\"ether1\",comment=\"WAN\"} 5000"
    ));
    assert!(body.contains(
        "mikrotik_interface_rx_packets_total{router=\"router1\",interface=\"ether1\",comment=\"WAN\"} 25"
    ));
    assert!(body.contains(
        "mikrotik_interface_tx_packets_total{router=\"router1\",interface=\"ether1\",comment=\"WAN\"} 35"
    ));
    assert!(
        body.contains(
            "mikrotik_interface_rx_errors_total{router=\"router1\",interface=\"ether1\",comment=\"WAN\"} 1"
        )
    );
    assert!(
        body.contains(
            "mikrotik_interface_tx_errors_total{router=\"router1\",interface=\"ether1\",comment=\"WAN\"} 4"
        )
    );
}

// --- /health endpoint ---

#[tokio::test]
async fn health_returns_200_for_empty_config() {
    let state = make_state(vec![]);
    let app = create_router(state);

    let resp = app
        .oneshot(Request::get("/health").body(String::new()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["status"], "healthy");
    assert!(health["routers"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn health_returns_unknown_before_first_scrape() {
    let state = make_state(vec![test_router("r1")]);
    let app = create_router(state);

    let resp = app
        .oneshot(Request::get("/health").body(String::new()).unwrap())
        .await
        .unwrap();

    // No scrapes yet → router status "unknown", overall "healthy" (unknown != degraded)
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["routers"][0]["status"], "unknown");
    assert!(
        !health["routers"][0]["has_successful_scrape"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn health_returns_healthy_after_successful_scrape() {
    let state = make_state(vec![test_router("r1")]);

    let label = RouterLabels {
        router: "r1".to_string(),
    };
    state.metrics.record_scrape_success(&label);

    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/health").body(String::new()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["routers"][0]["status"], "healthy");
    assert!(
        health["routers"][0]["has_successful_scrape"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn health_returns_degraded_on_errors_without_success() {
    let state = make_state(vec![test_router("r1")]);

    let label = RouterLabels {
        router: "r1".to_string(),
    };
    state.metrics.record_scrape_error(&label);

    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/health").body(String::new()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["routers"][0]["status"], "degraded");
}

#[tokio::test]
async fn health_returns_degraded_with_multiple_errors() {
    let state = make_state(vec![test_router("r1")]);

    let label = RouterLabels {
        router: "r1".to_string(),
    };
    state.metrics.record_scrape_error(&label);
    state.metrics.record_scrape_error(&label);
    state.metrics.record_scrape_error(&label);

    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/health").body(String::new()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["routers"][0]["status"], "degraded");
}

#[tokio::test]
async fn health_multi_router_partial_degradation() {
    let state = make_state(vec![test_router("healthy-r"), test_router("bad-r")]);

    state.metrics.record_scrape_success(&RouterLabels {
        router: "healthy-r".to_string(),
    });
    state.metrics.record_scrape_error(&RouterLabels {
        router: "bad-r".to_string(),
    });

    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/health").body(String::new()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["status"], "degraded");

    let routers = health["routers"].as_array().unwrap();
    let healthy = routers.iter().find(|r| r["name"] == "healthy-r").unwrap();
    let bad = routers.iter().find(|r| r["name"] == "bad-r").unwrap();
    assert_eq!(healthy["status"], "healthy");
    assert_eq!(bad["status"], "degraded");
}

// --- 404 for unknown routes ---

#[tokio::test]
async fn unknown_route_returns_404() {
    let state = make_state(vec![]);
    let app = create_router(state);

    let resp = app
        .oneshot(Request::get("/unknown").body(String::new()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_returns_degraded_when_all_routers_fail() {
    let state = make_state(vec![test_router("fail1"), test_router("fail2")]);

    // Record errors for both routers
    state.metrics.record_scrape_error(&RouterLabels {
        router: "fail1".to_string(),
    });
    state.metrics.record_scrape_error(&RouterLabels {
        router: "fail2".to_string(),
    });

    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/health").body(String::new()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["status"], "degraded");

    let routers = health["routers"].as_array().unwrap();
    assert_eq!(routers.len(), 2);
    assert_eq!(routers[0]["status"], "degraded");
    assert_eq!(routers[1]["status"], "degraded");
}

#[tokio::test]
async fn metrics_endpoint_handles_empty_router_list() {
    let state = make_state(vec![]);
    let app = create_router(state);

    let resp = app
        .oneshot(Request::get("/metrics").body(String::new()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    // Should contain base metrics even with no routers
    assert!(body.contains("mikrotik_connection_pool_size"));
    assert!(body.contains("mikrotik_connection_pool_active"));
}
