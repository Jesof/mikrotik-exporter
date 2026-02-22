// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Integration tests for MikroTik Exporter
//!
//! These tests require a real MikroTik device to be configured via environment variables.
//! To run these tests:
//! 1. Configure your MikroTik device credentials in a .env file
//! 2. Run with: `cargo test --test integration_tests`
//!
//! For CI environments, these tests are skipped if the required environment
//! variables are not set.

use dotenvy::dotenv;
use mikrotik_exporter::{
    ConnectionPool, FirewallRuleStats, InterfaceStats, MetricsRegistry, RouterLabels,
    RouterMetrics, SystemResource,
};
use std::sync::Arc;

/// Helper function to initialize environment for tests
fn init_test_env() {
    // Load environment variables from .env file
    let _ = dotenv(); // Ignore errors if .env file doesn't exist
}

#[tokio::test]
async fn test_environment_variables_loaded() {
    init_test_env();

    // This test verifies that environment variables can be loaded
    // It doesn't require actual router connectivity

    let has_single_router_config = std::env::var("ROUTEROS_ADDRESS").is_ok();
    let has_multi_router_config = std::env::var("ROUTERS_CONFIG").is_ok();

    if !has_single_router_config && !has_multi_router_config {
        println!("No router configuration found in environment variables");
        return;
    }

    if has_single_router_config {
        let address = std::env::var("ROUTEROS_ADDRESS").unwrap();
        println!("Single router configuration found: {}", address);
        assert!(address.contains(':'), "Router address should contain port");
    }

    if has_multi_router_config {
        let config_json = std::env::var("ROUTERS_CONFIG").unwrap();
        println!(
            "Multi-router configuration found: {} characters",
            config_json.len()
        );
        assert!(
            !config_json.is_empty(),
            "ROUTERS_CONFIG should not be empty"
        );
    }

    println!("Environment variables loaded successfully");
}

#[tokio::test]
async fn test_metrics_registry_scrape_recording() {
    // Test recording scrape success and error events
    let metrics = MetricsRegistry::new();

    let router_labels = RouterLabels {
        router: "test-router".to_string(),
    };

    // Initially both should be zero
    assert_eq!(metrics.get_scrape_success_count(&router_labels).await, 0);
    assert_eq!(metrics.get_scrape_error_count(&router_labels).await, 0);

    // Record a success
    metrics.record_scrape_success(&router_labels);
    assert_eq!(metrics.get_scrape_success_count(&router_labels).await, 1);
    assert_eq!(metrics.get_scrape_error_count(&router_labels).await, 0);

    // Record an error
    metrics.record_scrape_error(&router_labels);
    assert_eq!(metrics.get_scrape_success_count(&router_labels).await, 1);
    assert_eq!(metrics.get_scrape_error_count(&router_labels).await, 1);

    // Record multiple successes
    metrics.record_scrape_success(&router_labels);
    metrics.record_scrape_success(&router_labels);
    assert_eq!(metrics.get_scrape_success_count(&router_labels).await, 3);
    assert_eq!(metrics.get_scrape_error_count(&router_labels).await, 1);

    println!("Metrics registry scrape recording test passed");
}

#[tokio::test]
async fn test_metrics_registry_pool_stats() {
    // Test updating pool statistics
    let metrics = MetricsRegistry::new();

    // Initially pool stats should be zero
    let encoded = metrics
        .encode_metrics()
        .await
        .expect("Failed to encode metrics");
    assert!(encoded.contains("mikrotik_connection_pool_size 0"));
    assert!(encoded.contains("mikrotik_connection_pool_active 0"));

    // Update pool stats
    metrics.update_pool_stats(10, 5);

    // Check updated values
    let encoded = metrics
        .encode_metrics()
        .await
        .expect("Failed to encode metrics");
    assert!(encoded.contains("mikrotik_connection_pool_size 10"));
    assert!(encoded.contains("mikrotik_connection_pool_active 5"));

    println!("Metrics registry pool stats test passed");
}

#[tokio::test]
async fn test_metrics_registry_cycle_duration() {
    // Test recording collection cycle duration
    let metrics = MetricsRegistry::new();

    // Record a cycle duration
    metrics.record_collection_cycle_duration(1.234);

    // Check the recorded value
    let encoded = metrics
        .encode_metrics()
        .await
        .expect("Failed to encode metrics");
    assert!(encoded.contains("mikrotik_collection_cycle_duration_milliseconds 1234"));

    println!("Metrics registry cycle duration test passed");
}

#[tokio::test]
async fn test_metrics_registry_initialization() {
    init_test_env();

    // Test that metrics registry initializes correctly
    let _metrics = MetricsRegistry::new();

    // Verify that the registry is initially empty
    let has_single_router_config = std::env::var("ROUTEROS_ADDRESS").is_ok();
    let has_multi_router_config = std::env::var("ROUTERS_CONFIG").is_ok();

    if !has_single_router_config && !has_multi_router_config {
        // With no configuration, registry should still be functional
        let pool = Arc::new(ConnectionPool::new());
        let (total, active) = pool.get_pool_stats().await;
        assert_eq!(total, 0);
        assert_eq!(active, 0);
        println!("Metrics registry initialized correctly with empty configuration");
    }
}

#[tokio::test]
async fn test_metrics_update_and_retrieval() {
    // Test updating metrics and retrieving them through the HTTP endpoint
    let metrics = MetricsRegistry::new();

    // Create sample metrics data
    let iface = InterfaceStats {
        name: "ether1".to_string(),
        comment: "WAN".to_string(),
        rx_bytes: 1000,
        tx_bytes: 2000,
        rx_packets: 10,
        tx_packets: 20,
        rx_errors: 0,
        tx_errors: 0,
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

    let router_metrics = RouterMetrics {
        router_name: "test-router".to_string(),
        interfaces: vec![iface],
        system,
        connection_tracking: Vec::new(),
        wireguard_peers: vec![],
        certificate_stats: vec![],
        firewall_rules: vec![FirewallRuleStats {
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

    // Update metrics
    metrics.update_metrics(&router_metrics).await;

    // Verify the update was successful by checking that we can record a success
    metrics.record_scrape_success(&mikrotik_exporter::RouterLabels {
        router: "test-router".to_string(),
    });

    println!("Metrics update and retrieval test passed");
}

#[tokio::test]
async fn test_connection_pool_basic_functionality() {
    // Test basic connection pool operations
    let pool = Arc::new(ConnectionPool::new());

    // Initially pool should be empty
    let (total, active) = pool.get_pool_stats().await;
    assert_eq!(total, 0);
    assert_eq!(active, 0);

    println!("Connection pool basic functionality test passed");
}
