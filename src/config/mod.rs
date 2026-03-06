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
    pub const STARTUP_CONNECTIVITY_TEST: &str = "STARTUP_CONNECTIVITY_TEST";
    pub const STARTUP_CONNECTIVITY_TIMEOUT_SECS: &str = "STARTUP_CONNECTIVITY_TIMEOUT_SECS";
    pub const STRICT_STARTUP_MODE: &str = "STRICT_STARTUP_MODE";
    pub const ROUTEROS_ADDRESS: &str = "ROUTEROS_ADDRESS";
    pub const ROUTEROS_USERNAME: &str = "ROUTEROS_USERNAME";
    pub const ROUTEROS_PASSWORD: &str = "ROUTEROS_PASSWORD";
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
        self.validate_name()?;
        self.validate_address()?;
        self.validate_username()?;
        self.warn_on_weak_password();

        Ok(())
    }

    fn validate_name(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Router name cannot be empty".to_string());
        }

        if !self
            .name
            .chars()
            .all(|ch| ch.is_alphanumeric() || ch == '_' || ch == '-')
        {
            return Err(format!(
                "Router name '{}' contains invalid characters. Only alphanumeric, underscore, and hyphen are allowed",
                self.name
            ));
        }

        Ok(())
    }

    fn validate_address(&self) -> Result<(), String> {
        if !self.address.contains(':') {
            return Err(format!(
                "Invalid address format '{}': expected 'host:port'",
                self.address
            ));
        }

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

        if self.address.len() > 253 {
            return Err(format!(
                "Address '{}' is too long: maximum length is 253 characters",
                self.address
            ));
        }

        Ok(())
    }

    fn validate_username(&self) -> Result<(), String> {
        if self.username.trim().is_empty() {
            return Err(format!(
                "Username cannot be empty for router '{}'",
                self.name
            ));
        }

        if self.username.len() > 64 {
            return Err(format!(
                "Username for router '{}' is too long: maximum length is 64 characters",
                self.name
            ));
        }

        Ok(())
    }

    fn warn_on_weak_password(&self) {
        let password_len = self.password.expose_secret().len();
        if password_len > 0 && password_len < 8 {
            tracing::warn!(
                "Router '{}' has a weak password ({} characters): consider using a stronger password",
                self.name,
                password_len
            );
        }
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
        let server_addr = string_env_or_default(env_vars::SERVER_ADDR, defaults::SERVER_ADDR);
        let collection_interval_secs = parse_env_or_default(
            env_vars::COLLECTION_INTERVAL_SECONDS,
            defaults::COLLECTION_INTERVAL_SECS,
        );
        let gap_reset_threshold_secs = parse_env_or_default(
            env_vars::GAP_RESET_THRESHOLD_SECONDS,
            defaults::GAP_RESET_THRESHOLD_SECS,
        );
        let routers = validate_and_deduplicate_routers(load_router_configs());

        if routers.is_empty() {
            tracing::warn!(
                "No valid router configuration found. Service will start but /metrics will be empty."
            );
        }

        let startup_connectivity_test =
            parse_env_or_default(env_vars::STARTUP_CONNECTIVITY_TEST, false);
        let startup_connectivity_timeout_secs =
            parse_env_or_default(env_vars::STARTUP_CONNECTIVITY_TIMEOUT_SECS, 10);
        let strict_startup_mode = parse_env_or_default(env_vars::STRICT_STARTUP_MODE, false);

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
    /// # async fn example() -> mikrotik_exporter::Result<()> {
    /// # use mikrotik_exporter::Config;
    /// # use mikrotik_exporter::AppError;
    /// let config = Config::from_env();
    /// if config.startup_connectivity_test {
    ///     let failed = config.test_router_connectivity(config.startup_connectivity_timeout_secs).await;
    ///     if !failed.is_empty() {
    ///         eprintln!("Failed to connect to routers: {:?}", failed);
    ///         if config.strict_startup_mode {
    ///             return Err(AppError::Config("Startup connectivity check failed".to_string()));
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn test_router_connectivity(&self, timeout_secs: u64) -> Vec<String> {
        crate::startup::test_router_connectivity(self, timeout_secs).await
    }
}

fn load_router_configs() -> Vec<RouterConfig> {
    if let Ok(config_json) = std::env::var(env_vars::ROUTERS_CONFIG) {
        return serde_json::from_str(&config_json).unwrap_or_else(|error| {
            tracing::warn!(
                "Failed to parse ROUTERS_CONFIG: {}. Using empty list.",
                error
            );
            Vec::new()
        });
    }

    load_legacy_router_config().into_iter().collect()
}

fn load_legacy_router_config() -> Option<RouterConfig> {
    let address = std::env::var(env_vars::ROUTEROS_ADDRESS).ok();
    let username = string_env_or_default(env_vars::ROUTEROS_USERNAME, defaults::ROUTEROS_USERNAME);
    let password = string_env_or_default(env_vars::ROUTEROS_PASSWORD, defaults::ROUTEROS_PASSWORD);
    let password_secret = SecretString::new(password.into_boxed_str());

    if let Some(addr) = address {
        Some(RouterConfig {
            name: "default".to_string(),
            address: addr,
            username,
            password: password_secret,
        })
    } else {
        tracing::warn!(
            "No router configuration found. Service will start but /metrics will be empty."
        );
        None
    }
}

fn validate_and_deduplicate_routers(routers: Vec<RouterConfig>) -> Vec<RouterConfig> {
    let validated: Vec<RouterConfig> = routers
        .into_iter()
        .filter(|router| match router.validate() {
            Ok(()) => true,
            Err(error) => {
                tracing::error!("Invalid router '{}': {}", router.name, error);
                tracing::warn!("Skipping invalid router: {}", router.name);
                false
            }
        })
        .collect();

    let mut seen_names = std::collections::HashSet::new();
    validated
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
        .collect()
}

fn parse_env_or_default<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or(default)
}

fn string_env_or_default(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
