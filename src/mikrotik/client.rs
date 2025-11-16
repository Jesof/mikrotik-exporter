//! High-level MikroTik client

use crate::config::RouterConfig;
use std::sync::Arc;

use super::connection::{parse_interfaces, parse_system};
use super::pool::ConnectionPool;
use super::types::{RouterMetrics, SystemResource};

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
    /// system and interface statistics. Returns placeholder data on error.
    ///
    /// # Errors
    ///
    /// Returns an error if connection or authentication fails.
    pub async fn collect_metrics(
        &self,
    ) -> Result<RouterMetrics, Box<dyn std::error::Error + Send + Sync>> {
        match self.collect_real().await {
            Ok(m) => Ok(m),
            Err(e) => {
                tracing::error!("Router '{}' collection failed: {}", self.config.name, e);
                Ok(RouterMetrics {
                    router_name: self.config.name.clone(),
                    interfaces: Vec::new(),
                    system: SystemResource {
                        uptime: "0s".to_string(),
                        cpu_load: 0,
                        free_memory: 0,
                        total_memory: 0,
                        version: "unknown".to_string(),
                        board_name: "unknown".to_string(),
                    },
                })
            }
        }
    }

    async fn collect_real(
        &self,
    ) -> Result<RouterMetrics, Box<dyn std::error::Error + Send + Sync>> {
        // Get connection from pool
        let mut conn = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                &self.config.password,
            )
            .await?;

        let system_result = conn.command("/system/resource/print", &[]).await;
        let interfaces_result = conn.command("/interface/print", &[]).await;

        // Check if operations succeeded and record state
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

        // Always return connection to pool
        self.pool
            .release_connection(&self.config.address, &self.config.username, conn)
            .await;

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
    async fn test_collect_metrics_returns_placeholder_on_error() {
        let config = RouterConfig {
            name: "test-router".to_string(),
            address: "invalid:address".to_string(),
            username: "admin".to_string(),
            password: "password".to_string(),
        };

        let pool = Arc::new(ConnectionPool::new());
        let client = MikroTikClient::with_pool(config, pool);

        // This should fail to connect but return placeholder data
        let result = client.collect_metrics().await;
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert_eq!(metrics.router_name, "test-router");
        assert_eq!(metrics.interfaces.len(), 0);
        assert_eq!(metrics.system.version, "unknown");
        assert_eq!(metrics.system.uptime, "0s");
    }
}
