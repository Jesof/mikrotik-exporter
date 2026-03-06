// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! High-level `MikroTik` client

use crate::config::RouterConfig;
use crate::prelude::{AppError, Result};
use secrecy::ExposeSecret;
use std::sync::Arc;

use super::pool::ConnectionPool;
use super::responses::{
    parse_certificates, parse_connection_tracking, parse_firewall_rules, parse_interfaces,
    parse_system, parse_wireguard_peers,
};
use super::types::{
    CertificateStats, CollectionStatus, CollectionStatusParts, ConnectionTrackingStats, FetchState,
    FirewallRuleStats, InterfaceStats, RouterMetrics, SystemResource, WireGuardPeerStats,
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
    pub(crate) async fn collect_metrics(&self) -> Result<RouterMetrics> {
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
        } else {
            let failed_groups: Vec<&str> = [
                (!system_ok).then_some("system/interfaces"),
                (!conntrack_ok).then_some("connection tracking"),
                (!vpn_ok).then_some("VPN/certificates"),
                (!firewall_ok).then_some("firewall"),
            ]
            .iter()
            .filter_map(|&x| x)
            .collect();

            if !failed_groups.is_empty() {
                tracing::warn!(
                    "Router '{}' partial collection - failed groups: {:?}",
                    self.config.name,
                    failed_groups
                );
            }

            // If system group failed, it's a critical error
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

    async fn collect_group_system_interfaces(&self) -> Result<SystemInterfacesGroupData> {
        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                self.config.password.expose_secret(),
                Some("system"),
            )
            .await?;

        let conn = guard.get_mut();
        let system_result = conn
            .command(
                "/system/resource/print",
                &[".proplist=uptime,cpu-load,free-memory,total-memory,version,board-name"],
            )
            .await;
        let interfaces_result = conn
            .command(
                "/interface/print",
                &[".proplist=.id,name,comment,type,rx-byte,tx-byte,rx-packet,tx-packet,rx-error,tx-error,running"],
            )
            .await;

        let success = system_result.is_ok() && interfaces_result.is_ok();
        if success {
            self.pool
                .record_success(&self.config.address, &self.config.username, Some("system"))
                .await;
        } else {
            guard.mark_broken();
            self.pool
                .record_error(&self.config.address, &self.config.username, Some("system"))
                .await;
        }

        drop(guard);

        Ok(SystemInterfacesGroupData {
            system: parse_system(&system_result?),
            interfaces: parse_interfaces(&interfaces_result?),
        })
    }

    async fn collect_group_conntrack(&self) -> Result<ConntrackGroupData> {
        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                self.config.password.expose_secret(),
                Some("conntrack"),
            )
            .await?;

        let conn = guard.get_mut();
        let conntrack_v4_result = conn.command("/ip/firewall/connection/print", &[]).await;
        let conntrack_v6_result = conn.command("/ipv6/firewall/connection/print", &[]).await;
        let conntrack_v4_ok = conntrack_v4_result.is_ok();
        let conntrack_v6_ok = conntrack_v6_result.is_ok();

        let success = conntrack_v4_ok || conntrack_v6_ok;
        if success {
            self.pool
                .record_success(
                    &self.config.address,
                    &self.config.username,
                    Some("conntrack"),
                )
                .await;
        } else {
            guard.mark_broken();
            self.pool
                .record_error(
                    &self.config.address,
                    &self.config.username,
                    Some("conntrack"),
                )
                .await;
        }

        drop(guard);

        if !success {
            return Err(AppError::RouterOs(format!(
                "Router '{}' conntrack collection failed for both IPv4 and IPv6",
                self.config.name
            )));
        }

        let mut conntrack_v4 =
            parse_connection_tracking(&conntrack_v4_result.unwrap_or_default(), "ipv4");
        let conntrack_v6 =
            parse_connection_tracking(&conntrack_v6_result.unwrap_or_default(), "ipv6");

        conntrack_v4.extend(conntrack_v6);

        Ok(ConntrackGroupData {
            entries: conntrack_v4,
            complete_ok: conntrack_v4_ok && conntrack_v6_ok,
        })
    }

    async fn collect_group_vpn_certs(&self) -> Result<VpnCertGroupData> {
        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                self.config.password.expose_secret(),
                Some("vpn"),
            )
            .await?;

        let conn = guard.get_mut();
        let wireguard_peers_result = conn.command("/interface/wireguard/peers/print", &[]).await;
        let certificates_result = conn.command("/certificate/print", &[".detail"]).await;
        let wireguard_ok = wireguard_peers_result.is_ok();
        let certificates_ok = certificates_result.is_ok();

        let success = wireguard_ok || certificates_ok;
        if success {
            self.pool
                .record_success(&self.config.address, &self.config.username, Some("vpn"))
                .await;
        } else {
            guard.mark_broken();
            self.pool
                .record_error(&self.config.address, &self.config.username, Some("vpn"))
                .await;
        }

        drop(guard);

        if !success {
            return Err(AppError::RouterOs(format!(
                "Router '{}' VPN/certificate collection failed",
                self.config.name
            )));
        }

        Ok(VpnCertGroupData {
            wireguard_peers: parse_wireguard_peers(&wireguard_peers_result.unwrap_or_default()),
            certificate_stats: parse_certificates(&certificates_result.unwrap_or_default()),
            wireguard_ok,
            certificates_ok,
        })
    }

    async fn collect_group_firewall(&self) -> Result<FirewallGroupData> {
        const FIREWALL_PROPLIST: &str = ".proplist=.id,chain,action,bytes,packets,disabled";
        const FIREWALL_SECTIONS: [(&str, &str, &str); 8] = [
            ("/ip/firewall/filter/print", "ipv4", "filter"),
            ("/ip/firewall/nat/print", "ipv4", "nat"),
            ("/ip/firewall/mangle/print", "ipv4", "mangle"),
            ("/ip/firewall/raw/print", "ipv4", "raw"),
            ("/ipv6/firewall/filter/print", "ipv6", "filter"),
            ("/ipv6/firewall/nat/print", "ipv6", "nat"),
            ("/ipv6/firewall/mangle/print", "ipv6", "mangle"),
            ("/ipv6/firewall/raw/print", "ipv6", "raw"),
        ];

        let mut guard = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                self.config.password.expose_secret(),
                Some("firewall"),
            )
            .await?;

        let conn = guard.get_mut();

        let mut section_results = Vec::with_capacity(FIREWALL_SECTIONS.len());
        for (path, ip_version, section) in FIREWALL_SECTIONS {
            section_results.push((
                ip_version,
                section,
                conn.command(path, &[FIREWALL_PROPLIST]).await,
            ));
        }

        let success = section_results.iter().any(|(_, _, result)| result.is_ok());
        if success {
            self.pool
                .record_success(
                    &self.config.address,
                    &self.config.username,
                    Some("firewall"),
                )
                .await;
        } else {
            guard.mark_broken();
            self.pool
                .record_error(
                    &self.config.address,
                    &self.config.username,
                    Some("firewall"),
                )
                .await;
        }

        drop(guard);

        if !success {
            return Err(AppError::RouterOs(format!(
                "Router '{}' firewall collection failed",
                self.config.name
            )));
        }

        let mut firewall_rules = Vec::new();
        let mut complete_ok = true;
        for (ip_version, section, result) in section_results {
            complete_ok &= result.is_ok();
            firewall_rules.extend(parse_firewall_rules(
                &result.unwrap_or_default(),
                ip_version,
                section,
            ));
        }

        Ok(FirewallGroupData {
            rules: firewall_rules,
            complete_ok,
        })
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
            tracing::error!("{}", err);
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
