// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! High-level `MikroTik` client

use crate::config::RouterConfig;
use secrecy::ExposeSecret;
use std::sync::Arc;

use super::pool::ConnectionPool;
use super::responses::{
    parse_certificates, parse_connection_tracking, parse_firewall_rules, parse_interfaces,
    parse_system, parse_wireguard_peers,
};
use super::types::{
    CertificateStats, ConnectionTrackingStats, FirewallRuleStats, InterfaceStats, RouterMetrics,
    SystemResource, WireGuardPeerStats,
};

/// `MikroTik` `RouterOS` API client
///
/// Provides methods to connect to `MikroTik` routers via `RouterOS` API
/// and collect system resources, interface statistics, connection tracking,
/// `WireGuard` peers, and certificate information.
pub(crate) struct MikroTikClient {
    config: RouterConfig,
    pool: Arc<ConnectionPool>,
}

impl MikroTikClient {
    /// Creates a new `MikroTik` client with a shared connection pool
    #[must_use]
    pub(crate) fn with_pool(config: RouterConfig, pool: Arc<ConnectionPool>) -> Self {
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
    pub(crate) async fn collect_metrics(
        &self,
    ) -> Result<RouterMetrics, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::time::{Duration, timeout};

        const COLLECTION_TIMEOUT: Duration = Duration::from_secs(60);

        let result = timeout(COLLECTION_TIMEOUT, self.collect_parallel()).await;

        match result {
            Ok(Ok(metrics)) => Ok(metrics),
            Ok(Err(e)) => {
                tracing::error!("Router '{}' collection failed: {}", self.config.name, e);
                Err(e)
            }
            Err(_) => {
                let err = format!(
                    "Router '{}' collection timeout (>{}s)",
                    self.config.name,
                    COLLECTION_TIMEOUT.as_secs()
                );
                tracing::error!("{}", err);
                Err(err.into())
            }
        }
    }

    async fn collect_parallel(
        &self,
    ) -> Result<RouterMetrics, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::time::{Duration, timeout};

        const GROUP_SYSTEM_TIMEOUT: Duration = Duration::from_secs(20);
        const GROUP_CONNTRACK_TIMEOUT: Duration = Duration::from_secs(30);
        const GROUP_VPNCERT_TIMEOUT: Duration = Duration::from_secs(30);
        const GROUP_FIREWALL_TIMEOUT: Duration = Duration::from_secs(45);

        let (g1, g2, g3, g4) = tokio::join!(
            timeout(GROUP_SYSTEM_TIMEOUT, self.collect_group_system_interfaces()),
            timeout(GROUP_CONNTRACK_TIMEOUT, self.collect_group_conntrack()),
            timeout(GROUP_VPNCERT_TIMEOUT, self.collect_group_vpn_certs()),
            timeout(GROUP_FIREWALL_TIMEOUT, self.collect_group_firewall()),
        );

        let system_ok = g1.as_ref().map(Result::is_ok).unwrap_or(false);
        let conntrack_ok = g2.as_ref().map(Result::is_ok).unwrap_or(false);
        let vpn_ok = g3.as_ref().map(Result::is_ok).unwrap_or(false);
        let firewall_ok = g4.as_ref().map(Result::is_ok).unwrap_or(false);

        if system_ok && conntrack_ok && vpn_ok && firewall_ok {
            tracing::debug!(
                "Router '{}' collection succeeded for all groups",
                self.config.name
            );
        } else if !system_ok && !conntrack_ok && !vpn_ok && !firewall_ok {
            return Err(format!(
                "Router '{}' collection failed: all groups timed out or failed",
                self.config.name
            )
            .into());
        } else {
            let groups: Vec<&str> = [
                (!system_ok).then_some("system"),
                (!conntrack_ok).then_some("conntrack"),
                (!vpn_ok).then_some("vpn/certs"),
                (!firewall_ok).then_some("firewall"),
            ]
            .iter()
            .filter_map(|&x| x)
            .collect();

            tracing::warn!(
                "Router '{}' partial collection failure - failed groups: {:?}",
                self.config.name,
                groups
            );
        }

        let (system, interfaces) = g1.ok().and_then(Result::ok).unwrap_or_default();

        let connection_tracking = g2.ok().and_then(Result::ok).unwrap_or_default();

        let (wireguard_peers, certificate_stats) = g3.ok().and_then(Result::ok).unwrap_or_default();

        let firewall_rules = g4.ok().and_then(Result::ok).unwrap_or_default();

        Ok(RouterMetrics {
            router_name: self.config.name.clone(),
            interfaces,
            system,
            connection_tracking,
            wireguard_peers,
            certificate_stats,
            firewall_rules,
        })
    }

    async fn collect_group_system_interfaces(
        &self,
    ) -> Result<(SystemResource, Vec<InterfaceStats>), Box<dyn std::error::Error + Send + Sync>>
    {
        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                self.config.password.expose_secret(),
            )
            .await?;

        let conn = guard.get_mut();
        let system_result = conn.command("/system/resource/print", &[]).await;
        let interfaces_result = conn.command("/interface/print", &[]).await;

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

        drop(guard);

        let system = parse_system(&system_result?);
        let interfaces = parse_interfaces(&interfaces_result?);

        Ok((system, interfaces))
    }

    async fn collect_group_conntrack(
        &self,
    ) -> Result<Vec<ConnectionTrackingStats>, Box<dyn std::error::Error + Send + Sync>> {
        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                self.config.password.expose_secret(),
            )
            .await?;

        let conn = guard.get_mut();
        let conntrack_v4_result = conn.command("/ip/firewall/connection/print", &[]).await;
        let conntrack_v6_result = conn.command("/ipv6/firewall/connection/print", &[]).await;

        drop(guard);

        let mut conntrack_v4 =
            parse_connection_tracking(&conntrack_v4_result.unwrap_or_default(), "ipv4");
        let conntrack_v6 =
            parse_connection_tracking(&conntrack_v6_result.unwrap_or_default(), "ipv6");

        conntrack_v4.extend(conntrack_v6);

        Ok(conntrack_v4)
    }

    async fn collect_group_vpn_certs(
        &self,
    ) -> Result<
        (Vec<WireGuardPeerStats>, Vec<CertificateStats>),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                self.config.password.expose_secret(),
            )
            .await?;

        let conn = guard.get_mut();
        let wireguard_peers_result = conn.command("/interface/wireguard/peers/print", &[]).await;
        let certificates_result = conn.command("/certificate/print", &[".detail"]).await;

        drop(guard);

        let wireguard_peers = parse_wireguard_peers(&wireguard_peers_result.unwrap_or_default());
        let certificate_stats = parse_certificates(&certificates_result.unwrap_or_default());

        Ok((wireguard_peers, certificate_stats))
    }

    async fn collect_group_firewall(
        &self,
    ) -> Result<Vec<FirewallRuleStats>, Box<dyn std::error::Error + Send + Sync>> {
        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                self.config.password.expose_secret(),
            )
            .await?;

        let conn = guard.get_mut();

        let firewall_filter_v4_result = conn
            .command(
                "/ip/firewall/filter/print",
                &[".proplist=.id,chain,action,bytes,packets,disabled"],
            )
            .await;
        let firewall_nat_v4_result = conn
            .command(
                "/ip/firewall/nat/print",
                &[".proplist=.id,chain,action,bytes,packets,disabled"],
            )
            .await;
        let firewall_mangle_v4_result = conn
            .command(
                "/ip/firewall/mangle/print",
                &[".proplist=.id,chain,action,bytes,packets,disabled"],
            )
            .await;
        let firewall_raw_v4_result = conn
            .command(
                "/ip/firewall/raw/print",
                &[".proplist=.id,chain,action,bytes,packets,disabled"],
            )
            .await;
        let firewall_filter_v6_result = conn
            .command(
                "/ipv6/firewall/filter/print",
                &[".proplist=.id,chain,action,bytes,packets,disabled"],
            )
            .await;
        let firewall_nat_v6_result = conn
            .command(
                "/ipv6/firewall/nat/print",
                &[".proplist=.id,chain,action,bytes,packets,disabled"],
            )
            .await;
        let firewall_mangle_v6_result = conn
            .command(
                "/ipv6/firewall/mangle/print",
                &[".proplist=.id,chain,action,bytes,packets,disabled"],
            )
            .await;
        let firewall_raw_v6_result = conn
            .command(
                "/ipv6/firewall/raw/print",
                &[".proplist=.id,chain,action,bytes,packets,disabled"],
            )
            .await;

        drop(guard);

        let mut firewall_rules = Vec::new();

        firewall_rules.extend(parse_firewall_rules(
            &firewall_filter_v4_result.unwrap_or_default(),
            "ipv4",
            "filter",
        ));
        firewall_rules.extend(parse_firewall_rules(
            &firewall_nat_v4_result.unwrap_or_default(),
            "ipv4",
            "nat",
        ));
        firewall_rules.extend(parse_firewall_rules(
            &firewall_mangle_v4_result.unwrap_or_default(),
            "ipv4",
            "mangle",
        ));
        firewall_rules.extend(parse_firewall_rules(
            &firewall_raw_v4_result.unwrap_or_default(),
            "ipv4",
            "raw",
        ));

        firewall_rules.extend(parse_firewall_rules(
            &firewall_filter_v6_result.unwrap_or_default(),
            "ipv6",
            "filter",
        ));
        firewall_rules.extend(parse_firewall_rules(
            &firewall_nat_v6_result.unwrap_or_default(),
            "ipv6",
            "nat",
        ));
        firewall_rules.extend(parse_firewall_rules(
            &firewall_mangle_v6_result.unwrap_or_default(),
            "ipv6",
            "mangle",
        ));
        firewall_rules.extend(parse_firewall_rules(
            &firewall_raw_v6_result.unwrap_or_default(),
            "ipv6",
            "raw",
        ));

        Ok(firewall_rules)
    }

    /// Test connectivity to the router
    ///
    /// This method attempts to establish a connection to the router
    /// and authenticate to verify it is reachable and accessible.
    /// It's typically used for startup connectivity testing.
    ///
    /// # Errors
    ///
    /// Returns an error if connection or authentication fails.
    /// The error will contain details about the failure reason.
    ///
    /// This method is used internally by the configuration validation system
    /// to test router connectivity during application startup when the
    /// `STARTUP_CONNECTIVITY_TEST` configuration option is enabled.
    pub(crate) async fn test_connection(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::time::{Duration, timeout};

        const TEST_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

        if let Ok(result) = timeout(TEST_CONNECTION_TIMEOUT, self.test_connection_real()).await {
            result
        } else {
            let err = format!(
                "Router '{}' connection test timeout (>10s)",
                self.config.name
            );
            tracing::error!("{}", err);
            Err(err.into())
        }
    }

    async fn test_connection_real(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Get connection from pool (returns RAII guard that auto-releases on drop)
        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                self.config.password.expose_secret(),
            )
            .await?;

        let conn = guard.get_mut();

        // Execute a minimal command to test connectivity
        let result = conn.command("/system/resource/print", &[]).await;

        // Record connection state BEFORE dropping guard to prevent race condition
        if result.is_ok() {
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

        // Process the result
        let _sentences = result?;
        Ok(())
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
            password: "password".to_string().into(),
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
            password: "password".to_string().into(),
        };

        let pool = Arc::new(ConnectionPool::new());
        let client = MikroTikClient::with_pool(config, pool);

        // This should fail to connect and return an error
        let result = client.collect_metrics().await;
        assert!(result.is_err());
    }
}
