// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Configuration module for `MikroTik` Exporter application
//!
//! Loads and parses configuration from environment variables and JSON.

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

#[cfg(test)]
mod tests;

/// Default configuration values
mod defaults {
    pub const SERVER_ADDR: &str = "0.0.0.0:9090";
    pub const ROUTEROS_USERNAME: &str = "admin";
    pub const ROUTEROS_PASSWORD: &str = "";
    pub const COLLECTION_INTERVAL_SECS: u64 = 30;
    pub const GAP_RESET_THRESHOLD_SECS: u64 = 60; // More sensitive default
}

/// Environment variable names used by the application
mod env_vars {
    pub const SERVER_ADDR: &str = "SERVER_ADDR";
    pub const ROUTERS_CONFIG: &str = "ROUTERS_CONFIG";
    pub const COLLECTION_INTERVAL_SECONDS: &str = "COLLECTION_INTERVAL_SECONDS";
    pub const GAP_RESET_THRESHOLD_SECONDS: &str = "GAP_RESET_THRESHOLD_SECONDS";
}

/// Configuration for a single `MikroTik` router
///
/// # Router Name Uniqueness
///
/// **CRITICAL REQUIREMENT**: Router names MUST be unique across all routers.
/// Duplicate router names will cause:
/// - Metric label collisions in Prometheus
/// - Incorrect data aggregation in the metrics registry
/// - Race conditions in delta calculations for counter metrics
///
/// The configuration loading process validates and filters out routers with duplicate names,
/// logging errors for any duplicates found.
#[derive(Debug, Clone, Deserialize)]
pub struct RouterConfig {
    pub name: String,
    pub address: String,
    pub username: String,
    pub password: SecretString,
}

impl RouterConfig {
    /// Validates router configuration
    ///
    /// Performs comprehensive validation of all router configuration fields:
    /// - Router name must be non-empty and contain only valid characters
    /// - Address must be in valid 'host:port' format with valid port number
    /// - Username must be non-empty
    /// - Password length is checked for security best practices
    ///
    /// # Returns
    /// Returns `Ok(())` if validation passes, or `Err(String)` with a descriptive
    /// error message if validation fails.
    ///
    /// # Errors
    /// Returns `Err(String)` when any validation rule fails (empty name, invalid
    /// address format, empty username, or weak password).
    ///
    /// # Examples
    /// ```
    /// # use mikrotik_exporter::RouterConfig;
    /// let config = RouterConfig {
    ///     name: "my-router".to_string(),
    ///     address: "192.168.1.1:8728".to_string(),
    ///     username: "admin".to_string(),
    ///     password: "password".to_string().into(),
    /// };
    /// assert!(config.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<(), String> {
        // Validate name is not empty
        if self.name.trim().is_empty() {
            return Err("Router name cannot be empty".to_string());
        }

        // Validate name doesn't contain invalid characters for Prometheus labels
        // Prometheus labels must match [a-zA-Z_][a-zA-Z0-9_]*
        if !self
            .name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "Router name '{}' contains invalid characters. Only alphanumeric, underscore, and hyphen are allowed",
                self.name
            ));
        }

        // Validate address format (must contain port)
        if !self.address.contains(':') {
            return Err(format!(
                "Invalid address format '{}': expected 'host:port'",
                self.address
            ));
        }

        // Validate port number is valid (1-65535)
        if let Some(port_str) = self.address.split(':').next_back() {
            match port_str.parse::<u16>() {
                Ok(0) => {
                    return Err(format!(
                        "Invalid port number in address '{}': port cannot be 0",
                        self.address
                    ));
                }
                Err(_) => {
                    return Err(format!(
                        "Invalid port number in address '{}': expected numeric value 1-65535",
                        self.address
                    ));
                }
                _ => {}
            }
        } else {
            return Err(format!(
                "Invalid address format '{}': missing port number",
                self.address
            ));
        }

        // Validate address is not too long (practical limit for DNS names)
        if self.address.len() > 253 {
            return Err(format!(
                "Address '{}' is too long: maximum length is 253 characters",
                self.address
            ));
        }

        // Validate username is not empty
        if self.username.trim().is_empty() {
            return Err(format!(
                "Username cannot be empty for router '{}'",
                self.name
            ));
        }

        // Validate username length (RouterOS limit is 64 characters)
        if self.username.len() > 64 {
            return Err(format!(
                "Username for router '{}' is too long: maximum length is 64 characters",
                self.name
            ));
        }

        // Warn about weak password (optional security check)
        let password_len = self.password.expose_secret().len();
        if password_len > 0 && password_len < 8 {
            tracing::warn!(
                "Router '{}' has a weak password ({} characters): consider using a stronger password",
                self.name,
                password_len
            );
        }

        Ok(())
    }
}

/// Application-wide configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP server bind address (default: "0.0.0.0:9090")
    pub server_addr: String,
    /// List of configured routers to collect metrics from
    pub routers: Vec<RouterConfig>,
    /// Interval between metrics collection cycles in seconds (default: 30)
    pub collection_interval_secs: u64,
    /// Threshold for resetting counter baselines after gap in scrapes (default: 60)
    pub gap_reset_threshold_secs: u64,
    /// Whether to perform connectivity testing during startup (default: false)
    ///
    /// When enabled, the application will test connectivity to all configured routers
    /// during startup. If any router is unreachable, a warning will be logged.
    /// In strict mode, the application will exit with an error.
    pub startup_connectivity_test: bool,
    /// Timeout for connectivity tests during startup in seconds (default: 10)
    ///
    /// Maximum time to wait for each router connectivity test during startup.
    pub startup_connectivity_timeout_secs: u64,
    /// Whether to fail startup if any router is unreachable (default: false)
    ///
    /// When enabled with `startup_connectivity_test`, the application will exit
    /// with error code 1 if any configured router is unreachable during startup.
    pub strict_startup_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server_addr: defaults::SERVER_ADDR.to_string(),
            routers: vec![],
            collection_interval_secs: defaults::COLLECTION_INTERVAL_SECS,
            gap_reset_threshold_secs: defaults::GAP_RESET_THRESHOLD_SECS,
            startup_connectivity_test: false,
            startup_connectivity_timeout_secs: 10,
            strict_startup_mode: false,
        }
    }
}

impl Config {
    /// Loads configuration from environment variables
    ///
    /// Expects `dotenvy::dotenv()` to have been called by the application entry point.
    ///
    /// # Environment Variables
    ///
    /// - `SERVER_ADDR` - HTTP server bind address (default: "0.0.0.0:9090")
    /// - `ROUTERS_CONFIG` - JSON array of router configurations
    /// - `COLLECTION_INTERVAL_SECONDS` - Metrics collection interval in seconds (default: 30)
    /// - `GAP_RESET_THRESHOLD_SECONDS` - Threshold for resetting counter baselines (default: 60)
    /// - `STARTUP_CONNECTIVITY_TEST` - Test router connectivity during startup (default: false)
    /// - `STARTUP_CONNECTIVITY_TIMEOUT_SECS` - Timeout for startup connectivity tests (default: 10)
    /// - `STRICT_STARTUP_MODE` - Exit if any router is unreachable during startup (default: false)
    /// - `ROUTEROS_ADDRESS` - Legacy: single router address
    /// - `ROUTEROS_USERNAME` - Legacy: single router username (default: "admin")
    /// - `ROUTEROS_PASSWORD` - Legacy: single router password (default: "")
    ///
    /// # Returns
    ///
    /// Returns a `Config` instance with loaded values. Invalid router configurations
    /// are filtered out with warnings logged.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mikrotik_exporter::Config;
    ///
    /// // Load configuration from environment variables
    /// let config = Config::from_env();
    /// println!("Loaded configuration for {} router(s)", config.routers.len());
    /// ```
    pub fn from_env() -> Self {
        let server_addr = std::env::var(env_vars::SERVER_ADDR)
            .unwrap_or_else(|_| defaults::SERVER_ADDR.to_string());

        // Load routers configuration from JSON
        let routers = if let Ok(config_json) = std::env::var(env_vars::ROUTERS_CONFIG) {
            serde_json::from_str(&config_json).unwrap_or_else(|e| {
                tracing::warn!("Failed to parse ROUTERS_CONFIG: {}. Using empty list.", e);
                vec![]
            })
        } else {
            // Fallback: use legacy environment variables for single router
            let address = std::env::var("ROUTEROS_ADDRESS").ok();
            let username = std::env::var("ROUTEROS_USERNAME")
                .unwrap_or_else(|_| defaults::ROUTEROS_USERNAME.to_string());
            let password = std::env::var("ROUTEROS_PASSWORD")
                .unwrap_or_else(|_| defaults::ROUTEROS_PASSWORD.to_string());
            let password_secret = SecretString::new(password.into_boxed_str());

            if let Some(addr) = address {
                vec![RouterConfig {
                    name: "default".to_string(),
                    address: addr,
                    username,
                    password: password_secret,
                }]
            } else {
                tracing::warn!(
                    "No router configuration found. Service will start but /metrics will be empty."
                );
                vec![]
            }
        };

        let collection_interval_secs = std::env::var(env_vars::COLLECTION_INTERVAL_SECONDS)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(defaults::COLLECTION_INTERVAL_SECS);

        let gap_reset_threshold_secs = std::env::var(env_vars::GAP_RESET_THRESHOLD_SECONDS)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(defaults::GAP_RESET_THRESHOLD_SECS);

        // Validate and filter router configurations
        let routers: Vec<RouterConfig> = routers
            .into_iter()
            .filter(|router| match router.validate() {
                Ok(()) => true,
                Err(e) => {
                    tracing::error!("Invalid router '{}': {}", router.name, e);
                    tracing::warn!("Skipping invalid router: {}", router.name);
                    false
                }
            })
            .collect();

        // Check for duplicate router names
        let mut seen_names = std::collections::HashSet::new();
        let routers: Vec<RouterConfig> = routers
            .into_iter()
            .filter(|router| {
                if seen_names.contains(&router.name) {
                    tracing::error!(
                        "Duplicate router name '{}' found. Router names must be unique.",
                        router.name
                    );
                    false
                } else {
                    seen_names.insert(router.name.clone());
                    true
                }
            })
            .collect();

        if routers.is_empty() {
            tracing::warn!(
                "No valid router configuration found. Service will start but /metrics will be empty."
            );
        }

        // Load startup connectivity test configuration
        let startup_connectivity_test = std::env::var("STARTUP_CONNECTIVITY_TEST")
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(false);

        let startup_connectivity_timeout_secs = std::env::var("STARTUP_CONNECTIVITY_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10);

        let strict_startup_mode = std::env::var("STRICT_STARTUP_MODE")
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(false);

        Config {
            server_addr,
            routers,
            collection_interval_secs,
            gap_reset_threshold_secs,
            startup_connectivity_test,
            startup_connectivity_timeout_secs,
            strict_startup_mode,
        }
    }

    /// Test connectivity to all configured routers
    ///
    /// This method attempts to establish connections to all configured routers
    /// to verify they are reachable and accessible. It's typically used during
    /// application startup to detect connectivity issues early.
    ///
    /// # Arguments
    /// * `timeout_secs` - Timeout for each connectivity test in seconds
    ///
    /// # Returns
    /// Returns a vector of router names that failed connectivity tests.
    /// An empty vector indicates all routers are reachable.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use mikrotik_exporter::Config;
    /// let config = Config::from_env();
    /// if config.startup_connectivity_test {
    ///     let failed = config.test_router_connectivity(config.startup_connectivity_timeout_secs).await;
    ///     if !failed.is_empty() {
    ///         eprintln!("Failed to connect to routers: {:?}", failed);
    ///         if config.strict_startup_mode {
    ///             std::process::exit(1);
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn test_router_connectivity(&self, timeout_secs: u64) -> Vec<String> {
        use crate::mikrotik::{ConnectionPool, MikroTikClient};
        use std::sync::Arc;
        use tokio::time::{Duration, timeout};

        let pool = Arc::new(ConnectionPool::new());
        let mut failed_routers = Vec::new();

        for router in &self.routers {
            let client = MikroTikClient::with_pool(router.clone(), pool.clone());
            let timeout_duration = Duration::from_secs(timeout_secs);

            match timeout(timeout_duration, client.test_connection()).await {
                Ok(Ok(())) => {
                    tracing::info!("Successfully connected to router '{}'", router.name);
                }
                Ok(Err(e)) => {
                    tracing::warn!("Failed to connect to router '{}': {}", router.name, e);
                    failed_routers.push(router.name.clone());
                }
                Err(_) => {
                    tracing::warn!(
                        "Timeout connecting to router '{}' (>{timeout_secs}s)",
                        router.name
                    );
                    failed_routers.push(router.name.clone());
                }
            }
        }

        failed_routers
    }
}
