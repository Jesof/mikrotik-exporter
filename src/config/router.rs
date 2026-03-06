// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

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
        let Some((host, port_str)) = self.address.rsplit_once(':') else {
            return Err(format!(
                "Invalid address format '{}': expected 'host:port'",
                self.address
            ));
        };

        if host.is_empty() {
            return Err(format!(
                "Invalid address format '{}': host cannot be empty",
                self.address
            ));
        }

        if host.starts_with('[') {
            if !host.ends_with(']') || host.len() <= 2 {
                return Err(format!(
                    "Invalid IPv6 address format '{}': expected '[addr]:port'",
                    self.address
                ));
            }
        } else if host.contains(':') {
            return Err(format!(
                "Invalid IPv6 address format '{}': wrap IPv6 hosts in brackets",
                self.address
            ));
        }

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
