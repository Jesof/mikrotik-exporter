// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Configuration module for `MikroTik` Exporter application
//!
//! Loads and parses configuration from environment variables and JSON.

mod defaults;
mod env_vars;
mod loader;
mod router;

#[cfg(test)]
mod tests;

pub use self::router::{RouterConfig, RouterTlsConfig};

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
    /// Returns a validated `Config` instance with loaded values.
    ///
    /// # Errors
    /// Rejects malformed values, invalid routers, unknown JSON fields, and duplicate names.
    /// Invalid JSON never falls back to legacy configuration.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use mikrotik_exporter::Config;
    ///
    /// // Load configuration from environment variables
    /// let config = Config::from_env().unwrap();
    /// println!("Loaded configuration for {} router(s)", config.routers.len());
    /// ```
    pub fn from_env() -> crate::Result<Self> {
        Self::from_lookup(|key| match std::env::var(key) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(crate::AppError::Config(format!("Invalid Unicode in {key}")))
            }
        })
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn from_lookup(
        lookup: impl Fn(&str) -> crate::Result<Option<String>>,
    ) -> crate::Result<Self> {
        let server_addr =
            loader::string_env_or_default(&lookup, env_vars::SERVER_ADDR, defaults::SERVER_ADDR)?;
        let collection_interval_secs = loader::parse_env_or_default(
            &lookup,
            env_vars::COLLECTION_INTERVAL_SECONDS,
            defaults::COLLECTION_INTERVAL_SECS,
        )?;
        let gap_reset_threshold_secs = loader::parse_env_or_default(
            &lookup,
            env_vars::GAP_RESET_THRESHOLD_SECONDS,
            defaults::GAP_RESET_THRESHOLD_SECS,
        )?;
        let routers = loader::load_router_configs(&lookup)?;

        let startup_connectivity_test =
            loader::parse_env_or_default(&lookup, env_vars::STARTUP_CONNECTIVITY_TEST, false)?;
        let startup_connectivity_timeout_secs =
            loader::parse_env_or_default(&lookup, env_vars::STARTUP_CONNECTIVITY_TIMEOUT_SECS, 10)?;
        let strict_startup_mode =
            loader::parse_env_or_default(&lookup, env_vars::STRICT_STARTUP_MODE, false)?;

        let config = Config {
            server_addr,
            routers,
            collection_interval_secs,
            gap_reset_threshold_secs,
            startup_connectivity_test,
            startup_connectivity_timeout_secs,
            strict_startup_mode,
        };
        config.validate()?;
        Ok(config)
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> crate::Result<()> {
        use crate::AppError;

        self.server_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|_| AppError::Config("SERVER_ADDR must be an IP socket address".into()))?;
        for (key, value, maximum) in [
            (
                env_vars::COLLECTION_INTERVAL_SECONDS,
                self.collection_interval_secs,
                86_400,
            ),
            (
                env_vars::GAP_RESET_THRESHOLD_SECONDS,
                self.gap_reset_threshold_secs,
                604_800,
            ),
            (
                env_vars::STARTUP_CONNECTIVITY_TIMEOUT_SECS,
                self.startup_connectivity_timeout_secs,
                300,
            ),
        ] {
            if !(1..=maximum).contains(&value) {
                return Err(AppError::Config(format!(
                    "{key} must be between 1 and {maximum}"
                )));
            }
        }
        if self.strict_startup_mode && !self.startup_connectivity_test {
            return Err(AppError::Config(
                "STRICT_STARTUP_MODE requires STARTUP_CONNECTIVITY_TEST=true".into(),
            ));
        }
        if self.strict_startup_mode && self.routers.is_empty() {
            return Err(AppError::Config(
                "STRICT_STARTUP_MODE requires at least one router".into(),
            ));
        }
        let mut names = std::collections::HashSet::new();
        for router in &self.routers {
            router.validate().map_err(AppError::Config)?;
            if !names.insert(&router.name) {
                return Err(AppError::Config(format!(
                    "Duplicate router name '{}'",
                    router.name
                )));
            }
        }
        Ok(())
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
    /// let config = Config::from_env()?;
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
