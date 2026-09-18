// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use crate::prelude::{AppError, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio_rustls::rustls::pki_types::ServerName;

/// TLS settings for a single router (opt-in; insecure options are rejected).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct RouterTlsConfig {
    pub server_name: Option<String>,
    pub ca_file: Option<std::path::PathBuf>,
}

impl RouterTlsConfig {
    /// Resolves the TLS server name to verify for a router `address`.
    pub(crate) fn server_name_for_address(&self, address: &str) -> Result<ServerName<'static>> {
        let host = address
            .rsplit_once(':')
            .map(|(host, _)| host)
            .ok_or_else(|| AppError::Config("Invalid TLS router address".into()))?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let name = self.server_name.as_deref().unwrap_or(host);
        ServerName::try_from(name.to_string())
            .map_err(|_| AppError::Config("Invalid TLS server name".into()))
    }
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
/// Configuration loading and `Config::validate` reject the entire configuration on duplicates.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterConfig {
    pub name: String,
    pub address: String,
    pub username: String,
    pub password: SecretString,
    pub tls: Option<RouterTlsConfig>,
}

impl RouterConfig {
    /// Validates router configuration
    ///
    /// Performs comprehensive validation of all router configuration fields:
    /// - Router name must be non-empty and contain only valid characters
    /// - Address must be in valid 'host:port' format with valid port number
    /// - Username must be non-empty
    /// - TLS identity and CA path must be valid when configured
    /// - Short nonempty passwords produce a warning, not a validation error
    ///
    /// # Returns
    /// Returns `Ok(())` if validation passes, or `Err(AppError::Config)` with a
    /// descriptive error message if validation fails.
    ///
    /// # Errors
    /// Returns `Err(AppError::Config)` when any validation rule fails (empty name,
    /// invalid address format, empty username, or invalid TLS settings).
    ///
    /// # Examples
    /// ```
    /// # use mikrotik_exporter::RouterConfig;
    /// let config = RouterConfig {
    ///     name: "my-router".to_string(),
    ///     address: "192.168.1.1:8728".to_string(),
    ///     username: "admin".to_string(),
    ///     password: "password".to_string().into(),
    ///     tls: None,
    /// };
    /// assert!(config.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<()> {
        self.validate_name()?;
        self.validate_address()?;
        self.validate_username()?;
        if let Some(tls) = &self.tls {
            tls.server_name_for_address(&self.address)?;
            if tls
                .ca_file
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            {
                return Err(AppError::Config("TLS CA file path cannot be empty".into()));
            }
        }
        self.warn_on_weak_password();

        Ok(())
    }

    fn validate_name(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(AppError::Config("Router name cannot be empty".to_string()));
        }

        if !self
            .name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        {
            return Err(AppError::Config(format!(
                "Router name '{}' contains invalid characters. Only alphanumeric, underscore, and hyphen are allowed",
                self.name
            )));
        }

        if self.name.len() > 128 {
            return Err(AppError::Config(
                "Router name is too long: maximum length is 128 characters".into(),
            ));
        }
        Ok(())
    }

    fn validate_address(&self) -> Result<()> {
        let Some((host, port_str)) = self.address.rsplit_once(':') else {
            return Err(AppError::Config(format!(
                "Invalid address format '{}': expected 'host:port'",
                self.address
            )));
        };

        if host.is_empty() {
            return Err(AppError::Config(format!(
                "Invalid address format '{}': host cannot be empty",
                self.address
            )));
        }

        if host.starts_with('[') {
            if !host.ends_with(']') || host.len() <= 2 {
                return Err(AppError::Config(format!(
                    "Invalid IPv6 address format '{}': expected '[addr]:port'",
                    self.address
                )));
            }
            if host[1..host.len() - 1]
                .parse::<std::net::Ipv6Addr>()
                .is_err()
            {
                return Err(AppError::Config("Invalid IPv6 address".into()));
            }
        } else if host.contains(':') {
            return Err(AppError::Config(format!(
                "Invalid IPv6 address format '{}': wrap IPv6 hosts in brackets",
                self.address
            )));
        } else if !host.trim_end_matches('.').split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-')
        }) {
            return Err(AppError::Config("Invalid router hostname".into()));
        }

        match port_str.parse::<u16>() {
            Ok(0) => {
                return Err(AppError::Config(format!(
                    "Invalid port number in address '{}': port cannot be 0",
                    self.address
                )));
            }
            Err(_) => {
                return Err(AppError::Config(format!(
                    "Invalid port number in address '{}': expected numeric value 1-65535",
                    self.address
                )));
            }
            _ => {}
        }

        if self.address.len() > 253 {
            return Err(AppError::Config(format!(
                "Address '{}' is too long: maximum length is 253 characters",
                self.address
            )));
        }

        Ok(())
    }

    fn validate_username(&self) -> Result<()> {
        if self.username.trim().is_empty() {
            return Err(AppError::Config(format!(
                "Username cannot be empty for router '{}'",
                self.name
            )));
        }

        if self.username.len() > 64 {
            return Err(AppError::Config(format!(
                "Username for router '{}' is too long: maximum length is 64 characters",
                self.name
            )));
        }

        Ok(())
    }

    fn warn_on_weak_password(&self) {
        let password_len = self.password.expose_secret().len();
        if password_len > 0 && password_len < 8 {
            tracing::warn!(
                router = %self.name,
                password_len,
                "Weak password: consider using a stronger password"
            );
        }
    }
}
