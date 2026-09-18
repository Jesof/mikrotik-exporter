// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! High-level `MikroTik` client

mod groups;

use secrecy::ExposeSecret;
use std::sync::Arc;

use crate::config::RouterConfig;
use crate::prelude::{AppError, Result};

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
    certificates_complete: bool,
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
        use std::time::Duration;
        use tokio::time::timeout;

        const COLLECTION_TIMEOUT: Duration = Duration::from_secs(60);

        let result = timeout(COLLECTION_TIMEOUT, self.collect_parallel()).await;

        match result {
            Ok(Ok(metrics)) => Ok(metrics),
            Ok(Err(error)) => {
                tracing::error!(router = %self.config.name, %error, "Router collection failed");
                Err(error)
            }
            Err(_) => {
                tracing::error!(
                    router = %self.config.name,
                    timeout_secs = COLLECTION_TIMEOUT.as_secs(),
                    "Router collection timeout"
                );
                Err(AppError::Timeout("collection"))
            }
        }
    }

    async fn collect_parallel(&self) -> Result<RouterMetrics> {
        use std::time::Duration;
        use tokio::time::timeout;

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

        reject_invalid_snapshot([
            groups::inconsistent_snapshot_error(&g1),
            groups::inconsistent_snapshot_error(&g2),
            groups::inconsistent_snapshot_error(&g3),
            groups::inconsistent_snapshot_error(&g4),
        ])?;

        if system_ok && conntrack_ok && vpn_ok && firewall_ok {
            tracing::debug!(router = %self.config.name, "Router collection succeeded for all groups");
        } else {
            let failed_groups = groups::failed_group_names(&[
                ("system/interfaces", system_ok),
                ("connection tracking", conntrack_ok),
                ("VPN/certificates", vpn_ok),
                ("firewall", firewall_ok),
            ]);

            if !failed_groups.is_empty() {
                tracing::warn!(
                    router = %self.config.name,
                    failed_groups = ?failed_groups,
                    "Router partial collection"
                );
            }

            // If system group failed, it is a critical error.
            if !system_ok {
                return Err(AppError::RouterOs(format!(
                    "Router '{}' critical collection failure - system/interfaces group failed",
                    self.config.name
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
                certificates: if !vpn_group.certificates_ok {
                    FetchState::Failed
                } else if vpn_group.certificates_complete {
                    FetchState::Complete
                } else {
                    FetchState::Partial
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

    /// Record the connection health outcome for a collection group.
    ///
    /// Only connection-level failures discard the connection and increment the
    /// pool backoff counter. Query-level failures (for example a `!trap` for an
    /// optional table) leave a reusable connection and must not affect backoff.
    async fn record_group_result(
        &self,
        guard: &mut PooledConnectionGuard,
        connection_failed: bool,
    ) {
        if connection_failed {
            guard.mark_broken();
        }
        guard.record_result(!connection_failed).await;
    }

    /// Test connectivity to the router.
    pub(crate) async fn test_connection(&self) -> Result<()> {
        self.test_connection_real().await
    }

    async fn test_connection_real(&self) -> Result<()> {
        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                self.config.password.expose_secret(),
                None,
                self.config.tls.as_ref(),
            )
            .await?;

        let conn = guard.get_mut();

        let result = conn.command("/system/resource/print", &[]).await;

        if result.is_err() {
            guard.mark_broken();
        }
        guard.record_result(result.is_ok()).await;

        drop(guard);

        let _sentences = result?;
        Ok(())
    }
}

fn reject_invalid_snapshot(messages: [Option<&str>; 4]) -> Result<()> {
    match messages.into_iter().flatten().next() {
        Some(message) => Err(AppError::InvalidSnapshot(message.to_string())),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "explicit read-only collection from devices configured in local .env"]
    async fn test_real_router_single_snapshot() -> std::result::Result<(), &'static str> {
        let entries = dotenvy::dotenv_iter().map_err(|_| "cannot open dotenv")?;
        let mut values = std::collections::HashMap::new();
        for entry in entries {
            let (key, value) = entry.map_err(|_| "invalid dotenv syntax")?;
            values.insert(key, value);
        }
        let config = crate::config::Config::from_lookup(|key| Ok(values.get(key).cloned()))
            .map_err(|_| "invalid configuration (details redacted)")?;
        if config.routers.is_empty() {
            return Err("no configured devices");
        }
        println!("configured_devices={}", config.routers.len());
        let pool = Arc::new(ConnectionPool::new());
        for (index, router) in config.routers.into_iter().enumerate() {
            println!("device_index={index} tls={}", router.tls.is_some());
            let client = MikroTikClient::with_pool(router, pool.clone());
            tokio::time::timeout(std::time::Duration::from_secs(15), client.test_connection())
                .await
                .map_err(|_| "connectivity deadline exceeded")?
                .map_err(|_| "connectivity failed (details redacted)")?;
            println!("device_index={index} authenticated_resource_query=ok");
            let (conntrack, vpn, firewall) = tokio::join!(
                tokio::time::timeout(
                    std::time::Duration::from_secs(35),
                    groups::collect_group_conntrack(&client)
                ),
                tokio::time::timeout(
                    std::time::Duration::from_secs(35),
                    groups::collect_group_vpn_certs(&client)
                ),
                tokio::time::timeout(
                    std::time::Duration::from_secs(50),
                    groups::collect_group_firewall(&client)
                ),
            );
            match conntrack {
                Ok(Ok(data)) => println!("conntrack_query=ok complete={}", data.complete_ok),
                _ => println!("conntrack_query=failed"),
            }
            match vpn {
                Ok(Ok(data)) => println!("wireguard_query={}", data.wireguard_ok),
                _ => println!("vpn_cert_query=failed"),
            }
            match firewall {
                Ok(Ok(data)) => println!("firewall_query=ok complete={}", data.complete_ok),
                _ => println!("firewall_query=failed"),
            }
            let snapshot = client
                .collect_metrics()
                .await
                .map_err(|error| match error {
                    AppError::InvalidSnapshot(message) => {
                        println!(
                            "validation_missing_field={}",
                            message.starts_with("missing field ")
                        );
                        "snapshot validation failed (details redacted)"
                    }
                    _ => "collection failed (details redacted)",
                })?;
            let status = &snapshot.collection_status;
            println!(
                "device_index={index} system={} conntrack_complete={} wireguard={} certificates={} firewall_complete={}",
                status.system_interfaces_ok(),
                status.conntrack_complete_ok(),
                status.wireguard_ok(),
                status.certificates_ok(),
                status.firewall_complete_ok()
            );
            let registry = crate::metrics::MetricsRegistry::new();
            registry.update_metrics(&snapshot);
            let encoded = registry
                .encode_metrics()
                .await
                .map_err(|_| "encoding failed")?;
            if !encoded.ends_with("# EOF\n") || !encoded.contains("mikrotik_system_cpu_load_ratio{")
            {
                return Err("expected OpenMetrics data missing");
            }
            println!("device_index={index} openmetrics=ok");
            if !status.all_ok() {
                return Err("incomplete collection: see group booleans above");
            }
        }
        Ok(())
    }

    #[test]
    fn test_invalid_snapshot_remains_typed_for_every_group() {
        for group in 0..4 {
            let mut errors = [None; 4];
            errors[group] = Some("invalid snapshot");
            assert!(
                matches!(reject_invalid_snapshot(errors), Err(AppError::InvalidSnapshot(message)) if message == "invalid snapshot")
            );
        }
        assert!(reject_invalid_snapshot([None; 4]).is_ok());
    }

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
            tls: None,
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
            tls: None,
        };

        let pool = Arc::new(ConnectionPool::new());
        let client = MikroTikClient::with_pool(config, pool);

        let result = client.collect_metrics().await;
        assert!(result.is_err());
    }
}
