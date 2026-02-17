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
