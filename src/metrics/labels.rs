// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Label types for Prometheus metrics

use prometheus_client::encoding::EncodeLabelSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct InterfaceLabels {
    pub(crate) router: String,
    pub(crate) id: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct InterfaceInfoLabels {
    pub(crate) router: String,
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) comment: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RouterLabels {
    pub router: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct SystemInfoLabels {
    pub(crate) router: String,
    pub(crate) version: String,
    pub(crate) board: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct ConntrackLabels {
    pub(crate) router: String,
    pub(crate) src_address: String,
    pub(crate) protocol: String,
    pub(crate) ip_version: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct WireGuardPeerLabels {
    pub(crate) router: String,
    pub(crate) id: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct WireGuardPeerInfoLabels {
    pub(crate) router: String,
    pub(crate) id: String,
    pub(crate) interface: String,
    pub(crate) name: String,
    pub(crate) allowed_address: String,
    pub(crate) endpoint: String,
    pub(crate) comment: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct CertificateLabels {
    pub(crate) router: String,
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct FirewallRuleLabels {
    pub(crate) router: String,
    pub(crate) id: String,
    pub(crate) chain: String,
    pub(crate) action: String,
    pub(crate) ip_version: String,
    pub(crate) section: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct FirewallRuleInfoLabels {
    pub(crate) router: String,
    pub(crate) id: String,
    pub(crate) ip_version: String,
    pub(crate) section: String,
    pub(crate) comment: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_labels_creation() {
        let labels = InterfaceLabels {
            router: "router1".to_string(),
            id: "*1".to_string(),
        };

        assert_eq!(labels.router, "router1");
        assert_eq!(labels.id, "*1");
    }

    #[test]
    fn test_interface_info_labels_creation() {
        let labels = InterfaceInfoLabels {
            router: "router1".to_string(),
            id: "*1".to_string(),
            name: "ether1".to_string(),
            comment: "WAN".to_string(),
        };

        assert_eq!(labels.name, "ether1");
        assert_eq!(labels.comment, "WAN");
    }

    #[test]
    fn test_router_labels_creation() {
        let labels = RouterLabels {
            router: "main-router".to_string(),
        };

        assert_eq!(labels.router, "main-router");
    }

    #[test]
    fn test_system_info_labels_creation() {
        let labels = SystemInfoLabels {
            router: "router1".to_string(),
            version: "7.10".to_string(),
            board: "RB750Gr3".to_string(),
        };

        assert_eq!(labels.router, "router1");
        assert_eq!(labels.version, "7.10");
        assert_eq!(labels.board, "RB750Gr3");
    }

    #[test]
    fn test_firewall_rule_labels_creation() {
        let labels = FirewallRuleLabels {
            router: "router1".to_string(),
            id: "*1".to_string(),
            chain: "forward".to_string(),
            action: "accept".to_string(),
            ip_version: "ipv4".to_string(),
            section: "filter".to_string(),
        };

        assert_eq!(labels.router, "router1");
        assert_eq!(labels.id, "*1");
        assert_eq!(labels.chain, "forward");
        assert_eq!(labels.action, "accept");
        assert_eq!(labels.ip_version, "ipv4");
    }

    #[test]
    fn test_firewall_rule_info_labels_creation() {
        let labels = FirewallRuleInfoLabels {
            router: "router1".to_string(),
            id: "*1".to_string(),
            ip_version: "ipv4".to_string(),
            section: "filter".to_string(),
            comment: "Drop invalid".to_string(),
        };

        assert_eq!(labels.comment, "Drop invalid");
        assert_eq!(labels.ip_version, "ipv4");
        assert_eq!(labels.section, "filter");
    }
}
