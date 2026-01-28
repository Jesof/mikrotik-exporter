// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Configuration module for MikroTik Exporter application
//!
//! Loads and parses configuration from environment variables and JSON.

use serde::Deserialize;

#[cfg(test)]
mod tests;

/// Default configuration values
pub mod defaults {
    pub const SERVER_ADDR: &str = "0.0.0.0:9090";
    pub const ROUTEROS_USERNAME: &str = "admin";
    pub const ROUTEROS_PASSWORD: &str = "";
}

/// Environment variable names used by the application
pub mod env_vars {
    pub const SERVER_ADDR: &str = "SERVER_ADDR";
    pub const ROUTERS_CONFIG: &str = "ROUTERS_CONFIG";
}

/// Configuration for a single MikroTik router
#[derive(Debug, Clone, Deserialize)]
pub struct RouterConfig {
    pub name: String,
    pub address: String,
    pub username: String,
    pub password: String,
}

impl RouterConfig {
    /// Validates router configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate name is not empty
        if self.name.trim().is_empty() {
            return Err("Router name cannot be empty".to_string());
        }

        // Validate address format (must contain port)
        if !self.address.contains(':') {
            return Err(format!(
                "Invalid address format '{}': expected 'host:port'",
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

        Ok(())
    }
}

/// Application-wide configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub server_addr: String,
    pub routers: Vec<RouterConfig>,
    pub collection_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server_addr: defaults::SERVER_ADDR.to_string(),
            routers: vec![],
            collection_interval_secs: 30,
        }
    }
}

impl Config {
    /// Loads configuration from environment variables
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();

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

            if let Some(addr) = address {
                vec![RouterConfig {
                    name: "default".to_string(),
                    address: addr,
                    username,
                    password,
                }]
            } else {
                tracing::warn!(
                    "No router configuration found. Service will start but /metrics will be empty."
                );
                vec![]
            }
        };

        let collection_interval_secs = std::env::var("COLLECTION_INTERVAL_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);

        // Validate all router configurations
        for router in &routers {
            if let Err(e) = router.validate() {
                tracing::error!("Invalid router configuration: {}", e);
                tracing::warn!("Skipping invalid router: {}", router.name);
            }
        }

        Config {
            server_addr,
            routers,
            collection_interval_secs,
        }
    }
}
