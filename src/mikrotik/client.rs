// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! High-level `MikroTik` client

use crate::config::RouterConfig;
use crate::prelude::{AppError, Result};
use secrecy::ExposeSecret;
use std::sync::Arc;

use super::pool::{ConnectionPool, PooledConnectionGuard};
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

fn timeout_group_ok<T>(
    group: &std::result::Result<Result<T>, tokio::time::error::Elapsed>,
) -> bool {
    group.as_ref().map(Result::is_ok).unwrap_or(false)
}

fn failed_group_names(groups: &[(&'static str, bool)]) -> Vec<&'static str> {
    groups
        .iter()
        .filter_map(|(name, ok)| (!*ok).then_some(*name))
        .collect()
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

        let system_ok = timeout_group_ok(&g1);
        let conntrack_ok = timeout_group_ok(&g2);
        let vpn_ok = timeout_group_ok(&g3);
        let firewall_ok = timeout_group_ok(&g4);

        if system_ok && conntrack_ok && vpn_ok && firewall_ok {
            tracing::debug!(
                "Router '{}' collection succeeded for all groups",
                self.config.name
            );
        } else {
            let failed_groups = failed_group_names(&[
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
        let system_count = system_result.as_ref().map(Vec::len).unwrap_or(0);
        let interfaces_count = interfaces_result.as_ref().map(Vec::len).unwrap_or(0);

        if !success {
            tracing::warn!(
                "Router '{}' system group failed - system_ok: {}, interfaces_ok: {}",
                self.config.name,
                system_result.is_ok(),
                interfaces_result.is_ok()
            );
            if let Err(ref e) = system_result {
                tracing::debug!("Router '{}' system command error: {}", self.config.name, e);
            }
            if let Err(ref e) = interfaces_result {
                tracing::debug!(
                    "Router '{}' interfaces command error: {}",
                    self.config.name,
                    e
                );
            }
        }

        // Log if RouterOS returned empty responses (this is the RB5009 bug)
        if system_count == 0 && system_result.is_ok() {
            tracing::warn!(
                "Router '{}' /system/resource/print returned empty response (0 sentences)",
                self.config.name
            );
        }
        if interfaces_count == 0 && interfaces_result.is_ok() {
            tracing::warn!(
                "Router '{}' /interface/print returned empty response (0 sentences) - THIS IS THE BUG",
                self.config.name
            );
        }

        self.record_group_result(&mut guard, "system", success)
            .await;

        drop(guard);

        let system = system_result.map_err(|e| {
            tracing::warn!("Router '{}' system parse failed: {}", self.config.name, e);
            e
        })?;
        let interfaces = interfaces_result.map_err(|e| {
            tracing::warn!(
                "Router '{}' interfaces parse failed: {}",
                self.config.name,
                e
            );
            e
        })?;

        let system = parse_system(&system);
        let interfaces = parse_interfaces(&interfaces);

        Ok(SystemInterfacesGroupData { system, interfaces })
    }

    async fn collect_group_conntrack(&self) -> Result<ConntrackGroupData> {
        const CONNTRACK_COMMANDS: [(&str, &str); 2] = [
            ("/ip/firewall/connection/print", "ipv4"),
            ("/ipv6/firewall/connection/print", "ipv6"),
        ];

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
        let mut conntrack_results = Vec::with_capacity(CONNTRACK_COMMANDS.len());
        for (path, ip_version) in CONNTRACK_COMMANDS {
            conntrack_results.push((ip_version, conn.command(path, &[]).await));
        }

        let success = conntrack_results.iter().any(|(_, result)| result.is_ok());
        self.record_group_result(&mut guard, "conntrack", success)
            .await;

        drop(guard);

        if !success {
            return Err(AppError::RouterOs(format!(
                "Router '{}' conntrack collection failed for both IPv4 and IPv6",
                self.config.name
            )));
        }

        let mut entries = Vec::new();
        let mut complete_ok = true;
        for (ip_version, result) in conntrack_results {
            complete_ok &= result.is_ok();
            entries.extend(parse_connection_tracking(
                &result.unwrap_or_default(),
                ip_version,
            ));
        }

        Ok(ConntrackGroupData {
            entries,
            complete_ok,
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
        self.record_group_result(&mut guard, "vpn", success).await;

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
        self.record_group_result(&mut guard, "firewall", success)
            .await;

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
    fn test_failed_group_names_returns_only_failed_groups() {
        let groups = [
            ("system/interfaces", true),
            ("connection tracking", false),
            ("VPN/certificates", true),
            ("firewall", false),
        ];

        let failed = failed_group_names(&groups);

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

        // This should fail to connect and return an error
        let result = client.collect_metrics().await;
        assert!(result.is_err());
    }
}
