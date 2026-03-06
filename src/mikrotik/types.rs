// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Type definitions for `MikroTik` metrics

/// Statistics for a network interface
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub id: String,
    pub name: String,
    pub comment: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub running: bool,
}

/// System resource information from a `MikroTik` router
#[derive(Debug, Clone, Default)]
pub struct SystemResource {
    pub uptime: String,
    pub cpu_load: u64,
    pub free_memory: u64,
    pub total_memory: u64,
    pub version: String,
    pub board_name: String,
}

/// Connection tracking statistics per source address
#[derive(Debug, Clone, Default)]
pub struct ConnectionTrackingStats {
    pub src_address: String,
    pub protocol: String,
    pub connection_count: u64,
    pub ip_version: String,
}

/// Certificate information from a `MikroTik` router
#[derive(Debug, Clone, Default)]
pub struct CertificateStats {
    pub id: String,
    pub name: String,
    pub days_until_expiry: i64,
}

/// Statistics for a `WireGuard` peer
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WireGuardPeerStats {
    pub id: String,
    pub interface: String,
    pub name: String,
    pub comment: String,
    pub allowed_address: String,
    pub endpoint: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub latest_handshake: Option<u64>,
}

/// Statistics for firewall rules
#[derive(Debug, Clone, Default)]
pub struct FirewallRuleStats {
    pub id: String,
    pub comment: String,
    pub chain: String,
    pub action: String,
    pub bytes: u64,
    pub packets: u64,
    pub ip_version: String,
    pub section: String,
}

/// Complete metrics snapshot from a router
#[derive(Debug, Clone)]
pub struct CollectionStatus {
    bits: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchState {
    Failed,
    Partial,
    Complete,
}

impl FetchState {
    #[must_use]
    pub fn any_ok(self) -> bool {
        !matches!(self, Self::Failed)
    }

    #[must_use]
    pub fn complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CollectionStatusParts {
    pub system_interfaces: FetchState,
    pub conntrack: FetchState,
    pub wireguard: FetchState,
    pub certificates: FetchState,
    pub firewall: FetchState,
}

impl Default for CollectionStatusParts {
    fn default() -> Self {
        Self {
            system_interfaces: FetchState::Complete,
            conntrack: FetchState::Complete,
            wireguard: FetchState::Complete,
            certificates: FetchState::Complete,
            firewall: FetchState::Complete,
        }
    }
}

impl Default for CollectionStatus {
    fn default() -> Self {
        Self {
            bits: 0b11_1111_1111,
        }
    }
}

impl CollectionStatus {
    const SYSTEM_INTERFACES_OK: u16 = 1 << 0;
    const CONNTRACK_OK: u16 = 1 << 1;
    const VPN_CERTS_OK: u16 = 1 << 2;
    const FIREWALL_OK: u16 = 1 << 3;
    const CONNTRACK_COMPLETE_OK: u16 = 1 << 4;
    const WIREGUARD_OK: u16 = 1 << 5;
    const CERTIFICATES_OK: u16 = 1 << 6;
    const FIREWALL_COMPLETE_OK: u16 = 1 << 7;
    const FIREWALL_INFO_COMPLETE_OK: u16 = 1 << 8;

    #[must_use]
    pub fn from_group_results(results: [bool; 4]) -> Self {
        let [
            system_interfaces_ok,
            conntrack_ok,
            vpn_certs_ok,
            firewall_ok,
        ] = results;
        let mut bits = 0;
        if system_interfaces_ok {
            bits |= Self::SYSTEM_INTERFACES_OK;
        }
        if conntrack_ok {
            bits |= Self::CONNTRACK_OK;
        }
        if vpn_certs_ok {
            bits |= Self::VPN_CERTS_OK;
        }
        if firewall_ok {
            bits |= Self::FIREWALL_OK;
        }
        Self { bits }
    }

    #[must_use]
    pub fn from_parts(parts: CollectionStatusParts) -> Self {
        let mut bits = 0;
        if parts.system_interfaces.any_ok() {
            bits |= Self::SYSTEM_INTERFACES_OK;
        }
        if parts.conntrack.any_ok() {
            bits |= Self::CONNTRACK_OK;
        }
        if parts.wireguard.any_ok() || parts.certificates.any_ok() {
            bits |= Self::VPN_CERTS_OK;
        }
        if parts.firewall.any_ok() {
            bits |= Self::FIREWALL_OK;
        }
        if parts.conntrack.complete() {
            bits |= Self::CONNTRACK_COMPLETE_OK;
        }
        if parts.wireguard.any_ok() {
            bits |= Self::WIREGUARD_OK;
        }
        if parts.certificates.any_ok() {
            bits |= Self::CERTIFICATES_OK;
        }
        if parts.firewall.complete() {
            bits |= Self::FIREWALL_COMPLETE_OK;
            bits |= Self::FIREWALL_INFO_COMPLETE_OK;
        }
        Self { bits }
    }

    #[must_use]
    pub fn system_interfaces_ok(&self) -> bool {
        self.bits & Self::SYSTEM_INTERFACES_OK != 0
    }

    #[must_use]
    pub fn conntrack_ok(&self) -> bool {
        self.bits & Self::CONNTRACK_OK != 0
    }

    #[must_use]
    pub fn vpn_certs_ok(&self) -> bool {
        self.bits & Self::VPN_CERTS_OK != 0
    }

    #[must_use]
    pub fn conntrack_complete_ok(&self) -> bool {
        self.bits & Self::CONNTRACK_COMPLETE_OK != 0
    }

    #[must_use]
    pub fn wireguard_ok(&self) -> bool {
        self.bits & Self::WIREGUARD_OK != 0
    }

    #[must_use]
    pub fn certificates_ok(&self) -> bool {
        self.bits & Self::CERTIFICATES_OK != 0
    }

    #[must_use]
    pub fn firewall_ok(&self) -> bool {
        self.bits & Self::FIREWALL_OK != 0
    }

    #[must_use]
    pub fn firewall_complete_ok(&self) -> bool {
        self.bits & Self::FIREWALL_COMPLETE_OK != 0
    }

    #[must_use]
    pub fn firewall_info_complete_ok(&self) -> bool {
        self.bits & Self::FIREWALL_INFO_COMPLETE_OK != 0
    }

    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.system_interfaces_ok()
            && self.conntrack_ok()
            && self.vpn_certs_ok()
            && self.firewall_ok()
    }
}

/// Complete metrics snapshot from a router
#[derive(Debug, Clone, Default)]
pub struct RouterMetrics {
    pub router_name: String,
    pub collection_status: CollectionStatus,
    pub interfaces: Vec<InterfaceStats>,
    pub system: SystemResource,
    pub connection_tracking: Vec<ConnectionTrackingStats>,
    pub wireguard_peers: Vec<WireGuardPeerStats>,
    pub certificate_stats: Vec<CertificateStats>,
    pub firewall_rules: Vec<FirewallRuleStats>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_stats_creation() {
        let stats = InterfaceStats {
            id: "*1".to_string(),
            name: "ether1".to_string(),
            comment: "WAN".to_string(),
            rx_bytes: 1000,
            tx_bytes: 2000,
            rx_packets: 10,
            tx_packets: 20,
            rx_errors: 0,
            tx_errors: 0,
            running: true,
        };

        assert_eq!(stats.id, "*1");
        assert_eq!(stats.name, "ether1");
        assert_eq!(stats.comment, "WAN");
        assert_eq!(stats.rx_bytes, 1000);
        assert_eq!(stats.tx_bytes, 2000);
        assert!(stats.running);
    }

    #[test]
    fn test_system_resource_creation() {
        let resource = SystemResource {
            uptime: "1d2h3m4s".to_string(),
            cpu_load: 50,
            free_memory: 1024 * 1024 * 512,
            total_memory: 1024 * 1024 * 1024,
            version: "7.10".to_string(),
            board_name: "RB750Gr3".to_string(),
        };

        assert_eq!(resource.uptime, "1d2h3m4s");
        assert_eq!(resource.cpu_load, 50);
        assert_eq!(resource.version, "7.10");
        assert_eq!(resource.board_name, "RB750Gr3");
    }

    #[test]
    fn test_router_metrics_creation() {
        let metrics = RouterMetrics {
            router_name: "main-router".to_string(),
            collection_status: CollectionStatus::default(),
            interfaces: vec![InterfaceStats {
                id: "*1".to_string(),
                name: "ether1".to_string(),
                comment: "WAN".to_string(),
                rx_bytes: 1000,
                tx_bytes: 2000,
                rx_packets: 10,
                tx_packets: 20,
                rx_errors: 0,
                tx_errors: 0,
                running: true,
            }],
            system: SystemResource {
                uptime: "1d".to_string(),
                cpu_load: 10,
                free_memory: 1024,
                total_memory: 2048,
                version: "7.10".to_string(),
                board_name: "test".to_string(),
            },
            connection_tracking: Vec::new(),
            wireguard_peers: vec![WireGuardPeerStats {
                id: "*1".to_string(),
                interface: "wg1".to_string(),
                name: "peer1".to_string(),
                comment: "John".to_string(),
                allowed_address: "10.10.10.1/32".to_string(),
                endpoint: Some("192.168.1.1:51820".to_string()),
                rx_bytes: 1024,
                tx_bytes: 2048,
                latest_handshake: None,
            }],
            certificate_stats: vec![CertificateStats {
                id: "*1".to_string(),
                name: "cert1".to_string(),
                days_until_expiry: 30,
            }],
            firewall_rules: vec![FirewallRuleStats {
                id: "*1".to_string(),
                comment: "Drop invalid".to_string(),
                chain: "forward".to_string(),
                action: "accept".to_string(),
                bytes: 1024,
                packets: 5,
                ip_version: "ipv4".to_string(),
                section: "filter".to_string(),
            }],
        };

        assert_eq!(metrics.router_name, "main-router");
        assert_eq!(metrics.interfaces.len(), 1);
        assert_eq!(metrics.interfaces[0].id, "*1");
        assert_eq!(metrics.interfaces[0].name, "ether1");
        assert_eq!(metrics.system.version, "7.10");
        assert_eq!(metrics.wireguard_peers.len(), 1);
        assert_eq!(metrics.wireguard_peers[0].id, "*1");
        assert_eq!(metrics.certificate_stats.len(), 1);
        assert_eq!(metrics.certificate_stats[0].id, "*1");
        assert_eq!(metrics.certificate_stats[0].name, "cert1");
        assert_eq!(metrics.certificate_stats[0].days_until_expiry, 30);
        assert_eq!(metrics.firewall_rules.len(), 1);
        assert_eq!(metrics.firewall_rules[0].id, "*1");
        assert_eq!(metrics.firewall_rules[0].chain, "forward");
        assert_eq!(metrics.firewall_rules[0].action, "accept");
        assert_eq!(metrics.firewall_rules[0].bytes, 1024);
        assert_eq!(metrics.firewall_rules[0].packets, 5);
        assert_eq!(metrics.firewall_rules[0].ip_version, "ipv4");
        assert_eq!(metrics.firewall_rules[0].section, "filter");
    }

    #[test]
    fn test_interface_stats_clone() {
        let stats = InterfaceStats {
            id: "*1".to_string(),
            name: "ether1".to_string(),
            comment: "WAN".to_string(),
            rx_bytes: 1000,
            tx_bytes: 2000,
            rx_packets: 10,
            tx_packets: 20,
            rx_errors: 0,
            tx_errors: 0,
            running: true,
        };

        let cloned = stats.clone();
        assert_eq!(stats.id, cloned.id);
        assert_eq!(stats.name, cloned.name);
        assert_eq!(stats.comment, cloned.comment);
        assert_eq!(stats.rx_bytes, cloned.rx_bytes);
    }
}
