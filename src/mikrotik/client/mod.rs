// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! High-level `MikroTik` client

mod groups;

use crate::config::RouterConfig;
use crate::prelude::{AppError, Result};
use secrecy::ExposeSecret;
use std::sync::Arc;

use super::pool::{ConnectionPool, PooledConnectionGuard};
use super::types::{
    CertificateStats, CollectionStatus, CollectionStatusParts, ConnectionTrackingStats, FetchState,
    FirewallRuleStats, InterfaceStats, RouterMetrics, SystemResource, WireGuardPeerStats,
};

/// `MikroTik` `RouterOS` API client
///
/// Provides methods to connect to `RouterOS` API and collect:
/// system resources, interface statistics, connection tracking,
/// `WireGuard` peers, and certificate information.
pub(crate) struct MikroTikClient {
    config: RouterConfig,
    pool: Arc<ConnectionPool>,
}

#[derive(Default)]
struct SystemInterfacesGroupData {
    system: SystemResource,
    interfaces: Vec<InterfaceStats>,
}

#[derive(Default)]
struct ConntrackGroupData {
    entries: Vec<ConnectionTrackingStats>,
    complete_ok: bool,
}

#[derive(Default)]
struct VpnCertGroupData {
    wireguard_peers: Vec<WireGuardPeerStats>,
    certificate_stats: Vec<CertificateStats>,
    wireguard_ok: bool,
    certificates_ok: bool,
}

#[derive(Default)]
struct FirewallGroupData {
    rules: Vec<FirewallRuleStats>,
    complete_ok: bool,
}

impl MikroTikClient {
    /// Creates a new `MikroTik` client with a shared connection pool.
    #[must_use]
    pub(crate) fn with_pool(config: RouterConfig, pool: Arc<ConnectionPool>) -> Self {
        Self { config, pool }
    }

    /// Collects metrics from the router.
    pub(crate) async fn collect_metrics(&self) -> Result<RouterMetrics> {
        use tokio::time::{Duration, timeout};

        const COLLECTION_TIMEOUT: Duration = Duration::from_secs(60);

        let result = timeout(COLLECTION_TIMEOUT, self.collect_parallel()).await;

        match result {
            Ok(Ok(metrics)) => Ok(metrics),
            Ok(Err(error)) => {
                tracing::error!("Router '{}' collection failed: {}", self.config.name, error);
                Err(error)
            }
            Err(_) => {
                let err = format!(
                    "Router '{}' collection timeout (>{}s)",
                    self.config.name,
                    COLLECTION_TIMEOUT.as_secs()
                );
                tracing::error!("{err}");
                Err(AppError::RouterOs(err))
            }
        }
    }

    async fn collect_parallel(&self) -> Result<RouterMetrics> {
        use tokio::time::{Duration, timeout};

        const GROUP_SYSTEM_TIMEOUT: Duration = Duration::from_secs(20);
        const GROUP_CONNTRACK_TIMEOUT: Duration = Duration::from_secs(30);
        const GROUP_VPNCERT_TIMEOUT: Duration = Duration::from_secs(30);
        const GROUP_FIREWALL_TIMEOUT: Duration = Duration::from_secs(45);

        let (g1, g2, g3, g4) = tokio::join!(
            timeout(
                GROUP_SYSTEM_TIMEOUT,
                groups::collect_group_system_interfaces(self)
            ),
            timeout(
                GROUP_CONNTRACK_TIMEOUT,
                groups::collect_group_conntrack(self)
            ),
            timeout(GROUP_VPNCERT_TIMEOUT, groups::collect_group_vpn_certs(self)),
            timeout(GROUP_FIREWALL_TIMEOUT, groups::collect_group_firewall(self)),
        );

        let system_ok = groups::timeout_group_ok(&g1);
        let conntrack_ok = groups::timeout_group_ok(&g2);
        let vpn_ok = groups::timeout_group_ok(&g3);
        let firewall_ok = groups::timeout_group_ok(&g4);

        if system_ok && conntrack_ok && vpn_ok && firewall_ok {
            tracing::debug!(
                "Router '{}' collection succeeded for all groups",
                self.config.name
            );
        } else {
            let failed_groups = groups::failed_group_names(&[
                ("system/interfaces", system_ok),
                ("connection tracking", conntrack_ok),
                ("VPN/certificates", vpn_ok),
                ("firewall", firewall_ok),
            ]);

            if !failed_groups.is_empty() {
                tracing::warn!(
                    "Router '{}' partial collection - failed groups: {:?}",
                    self.config.name,
                    failed_groups
                );
            }

            // If system group failed, it is a critical error.
            if !system_ok {
                return Err(AppError::RouterOs(format!(
                    "Router '{}' critical collection failure - system/interfaces group failed",
                    self.config.name
                )));
            }

            if let Some(inconsistent) = [
                groups::inconsistent_snapshot_error(&g2),
                groups::inconsistent_snapshot_error(&g3),
                groups::inconsistent_snapshot_error(&g4),
            ]
            .into_iter()
            .flatten()
            .next()
            {
                return Err(AppError::RouterOs(format!(
                    "Router '{}' {}",
                    self.config.name, inconsistent
                )));
            }
        }

        let system_group = g1.ok().and_then(Result::ok).unwrap_or_default();
        let conntrack_group = g2.ok().and_then(Result::ok).unwrap_or_default();
        let vpn_group = g3.ok().and_then(Result::ok).unwrap_or_default();
        let firewall_group = g4.ok().and_then(Result::ok).unwrap_or_default();

        Ok(RouterMetrics {
            router_name: self.config.name.clone(),
            collection_status: CollectionStatus::from_parts(CollectionStatusParts {
                system_interfaces: if system_ok {
                    FetchState::Complete
                } else {
                    FetchState::Failed
                },
                conntrack: if !conntrack_ok {
                    FetchState::Failed
                } else if conntrack_group.complete_ok {
                    FetchState::Complete
                } else {
                    FetchState::Partial
                },
                wireguard: if vpn_group.wireguard_ok {
                    FetchState::Complete
                } else {
                    FetchState::Failed
                },
                certificates: if vpn_group.certificates_ok {
                    FetchState::Complete
                } else {
                    FetchState::Failed
                },
                firewall: if !firewall_ok {
                    FetchState::Failed
                } else if firewall_group.complete_ok {
                    FetchState::Complete
                } else {
                    FetchState::Partial
                },
            }),
            interfaces: system_group.interfaces,
            system: system_group.system,
            connection_tracking: conntrack_group.entries,
            wireguard_peers: vpn_group.wireguard_peers,
            certificate_stats: vpn_group.certificate_stats,
            firewall_rules: firewall_group.rules,
        })
    }

    async fn record_group_result(
        &self,
        guard: &mut PooledConnectionGuard,
        group: &'static str,
        success: bool,
    ) {
        if success {
            self.pool
                .record_success(&self.config.address, &self.config.username, Some(group))
                .await;
        } else {
            guard.mark_broken();
            self.pool
                .record_error(&self.config.address, &self.config.username, Some(group))
                .await;
        }
    }

    /// Test connectivity to the router.
    pub(crate) async fn test_connection(&self) -> Result<()> {
        use tokio::time::{Duration, timeout};

        const TEST_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

        if let Ok(result) = timeout(TEST_CONNECTION_TIMEOUT, self.test_connection_real()).await {
            result
        } else {
            let err = format!(
                "Router '{}' connection test timeout (>10s)",
                self.config.name
            );
            tracing::error!("{err}");
            Err(AppError::RouterOs(err))
        }
    }

    async fn test_connection_real(&self) -> Result<()> {
        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                self.config.password.expose_secret(),
                None,
            )
            .await?;

        let conn = guard.get_mut();

        let result = conn.command("/system/resource/print", &[]).await;

        if result.is_ok() {
            self.pool
                .record_success(&self.config.address, &self.config.username, None)
                .await;
        } else {
            self.pool
                .record_error(&self.config.address, &self.config.username, None)
                .await;
        }

        drop(guard);

        let _sentences = result?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failed_group_names_returns_only_failed_groups() {
        let groups = [
            ("system/interfaces", true),
            ("connection tracking", false),
            ("VPN/certificates", true),
            ("firewall", false),
        ];

        let failed = groups::failed_group_names(&groups);

        assert_eq!(failed, vec!["connection tracking", "firewall"]);
    }

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

        let result = client.collect_metrics().await;
        assert!(result.is_err());
    }
}
