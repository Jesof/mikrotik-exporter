// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! High-level MikroTik client

use crate::config::RouterConfig;
use std::sync::Arc;

use super::connection::{parse_interfaces, parse_system};
use super::pool::ConnectionPool;
use super::types::RouterMetrics;

/// `MikroTik` `RouterOS` API client
///
/// Provides methods to connect to `MikroTik` routers via `RouterOS` API
/// and collect system and interface metrics.
pub struct MikroTikClient {
    config: RouterConfig,
    pool: Arc<ConnectionPool>,
}

impl MikroTikClient {
    /// Creates a new `MikroTik` client with a shared connection pool
    #[must_use]
    pub fn with_pool(config: RouterConfig, pool: Arc<ConnectionPool>) -> Self {
        Self { config, pool }
    }

    /// Collects metrics from the router
    ///
    /// This method connects to the router, authenticates, and retrieves
    /// system and interface statistics.
    ///
    /// # Errors
    ///
    /// Returns an error if connection, authentication, or data retrieval fails.
    /// On error, metrics are not updated, preserving the last successful values.
    pub async fn collect_metrics(
        &self,
    ) -> Result<RouterMetrics, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::time::{Duration, timeout};

        const COLLECTION_TIMEOUT: Duration = Duration::from_secs(30);

        match timeout(COLLECTION_TIMEOUT, self.collect_real()).await {
            Ok(Ok(m)) => Ok(m),
            Ok(Err(e)) => {
                tracing::error!("Router '{}' collection failed: {}", self.config.name, e);
                Err(e)
            }
            Err(_) => {
                let err = format!("Router '{}' collection timeout (>30s)", self.config.name);
                tracing::error!("{}", err);
                Err(err.into())
            }
        }
    }

    async fn collect_real(
        &self,
    ) -> Result<RouterMetrics, Box<dyn std::error::Error + Send + Sync>> {
        // Get connection from pool (returns RAII guard that auto-releases on drop)
        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                &self.config.password,
            )
            .await?;

        let conn = guard.get_mut();
        let system_result = conn.command("/system/resource/print", &[]).await;
        let interfaces_result = conn.command("/interface/print", &[]).await;

        // Record connection state BEFORE dropping guard to prevent race condition
        let success = system_result.is_ok() && interfaces_result.is_ok();
        if success {
            self.pool
                .record_success(&self.config.address, &self.config.username)
                .await;
        } else {
            self.pool
                .record_error(&self.config.address, &self.config.username)
                .await;
        }

        // Explicitly drop guard AFTER state is recorded
        drop(guard);

        // Now process results after connection is returned to pool with correct state
        let system_sentences = system_result?;
        let interfaces_sentences = interfaces_result?;

        let system = parse_system(&system_sentences);
        let interfaces = parse_interfaces(&interfaces_sentences);

        Ok(RouterMetrics {
            router_name: self.config.name.clone(),
            interfaces,
            system,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mikrotik_client_creation() {
        let config = RouterConfig {
            name: "test-router".to_string(),
            address: "192.168.1.1:8728".to_string(),
            username: "admin".to_string(),
            password: "password".to_string(),
        };

        let pool = Arc::new(ConnectionPool::new());
        let client = MikroTikClient::with_pool(config.clone(), pool);

        assert_eq!(client.config.name, "test-router");
        assert_eq!(client.config.address, "192.168.1.1:8728");
    }

    #[tokio::test]
    async fn test_collect_metrics_returns_error_on_failure() {
        let config = RouterConfig {
            name: "test-router".to_string(),
            address: "invalid:address".to_string(),
            username: "admin".to_string(),
            password: "password".to_string(),
        };

        let pool = Arc::new(ConnectionPool::new());
        let client = MikroTikClient::with_pool(config, pool);

        // This should fail to connect and return an error
        let result = client.collect_metrics().await;
        assert!(result.is_err());
    }
}
