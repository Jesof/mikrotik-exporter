// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Label types for Prometheus metrics

use prometheus_client::encoding::EncodeLabelSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct InterfaceLabels {
    pub(crate) router: String,
    pub(crate) interface: String,
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
pub(crate) struct WireGuardInterfaceLabels {
    pub(crate) router: String,
    pub(crate) interface: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct WireGuardPeerLabels {
    pub(crate) router: String,
    pub(crate) interface: String,
    pub(crate) allowed_address: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct WireGuardPeerInfoLabels {
    pub(crate) router: String,
    pub(crate) interface: String,
    pub(crate) allowed_address: String,
    pub(crate) name: String,
    pub(crate) endpoint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_labels_creation() {
        let labels = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether1".to_string(),
        };

        assert_eq!(labels.router, "router1");
        assert_eq!(labels.interface, "ether1");
    }

    #[test]
    fn test_interface_labels_equality() {
        let labels1 = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether1".to_string(),
        };

        let labels2 = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether1".to_string(),
        };

        assert_eq!(labels1, labels2);
    }

    #[test]
    fn test_interface_labels_inequality() {
        let labels1 = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether1".to_string(),
        };

        let labels2 = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether2".to_string(),
        };

        assert_ne!(labels1, labels2);
    }

    #[test]
    fn test_router_labels_creation() {
        let labels = RouterLabels {
            router: "main-router".to_string(),
        };

        assert_eq!(labels.router, "main-router");
    }

    #[test]
    fn test_router_labels_hash() {
        use std::collections::HashMap;

        let labels1 = RouterLabels {
            router: "router1".to_string(),
        };

        let labels2 = RouterLabels {
            router: "router1".to_string(),
        };

        let mut map = HashMap::new();
        map.insert(labels1, 100);

        assert_eq!(map.get(&labels2), Some(&100));
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
    fn test_system_info_labels_clone() {
        let labels = SystemInfoLabels {
            router: "router1".to_string(),
            version: "7.10".to_string(),
            board: "RB750Gr3".to_string(),
        };

        let cloned = labels.clone();
        assert_eq!(labels, cloned);
    }

    #[test]
    fn test_labels_debug_format() {
        let labels = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether1".to_string(),
        };

        let debug_str = format!("{:?}", labels);
        assert!(debug_str.contains("router1"));
        assert!(debug_str.contains("ether1"));
    }
}
