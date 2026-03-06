// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Interface parsing

use crate::mikrotik::types::InterfaceStats;
use std::collections::HashMap;

use super::common::parse_u64_field;

pub(crate) fn parse_interfaces(sentences: &[HashMap<String, String>]) -> Vec<InterfaceStats> {
    let mut out = Vec::new();
    for s in sentences {
        if let (Some(id), Some(name)) = (s.get(".id"), s.get("name")) {
            out.push(InterfaceStats {
                id: id.clone(),
                name: name.clone(),
                comment: s.get("comment").cloned().unwrap_or_default(),
                rx_bytes: parse_u64_field(s, "rx-byte", "interface stats"),
                tx_bytes: parse_u64_field(s, "tx-byte", "interface stats"),
                rx_packets: parse_u64_field(s, "rx-packet", "interface stats"),
                tx_packets: parse_u64_field(s, "tx-packet", "interface stats"),
                rx_errors: parse_u64_field(s, "rx-error", "interface stats"),
                tx_errors: parse_u64_field(s, "tx-error", "interface stats"),
                running: s.get("running").is_some_and(|v| v == "true"),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_interfaces_complete() {
        let mut iface1 = HashMap::new();
        iface1.insert(".id".to_string(), "*1".to_string());
        iface1.insert("name".to_string(), "ether1".to_string());
        iface1.insert("comment".to_string(), "WAN".to_string());
        iface1.insert("type".to_string(), "ether".to_string());

        iface1.insert("running".to_string(), "true".to_string());

        let mut iface2 = HashMap::new();
        iface2.insert(".id".to_string(), "*2".to_string());
        iface2.insert("name".to_string(), "ether2".to_string());
        iface2.insert("type".to_string(), "ether".to_string());
        iface2.insert("running".to_string(), "false".to_string());

        let result = parse_interfaces(&[iface1, iface2]);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "*1");
        assert_eq!(result[0].name, "ether1");
        assert_eq!(result[0].comment, "WAN");
        assert!(result[0].running);
        assert_eq!(result[1].id, "*2");
        assert_eq!(result[1].name, "ether2");
        assert!(!result[1].running);
    }

    #[test]
    fn test_parse_interfaces_missing_values() {
        let mut iface = HashMap::new();
        iface.insert(".id".to_string(), "*1".to_string());
        iface.insert("name".to_string(), "ether1".to_string());
        iface.insert("type".to_string(), "ether".to_string());

        let result = parse_interfaces(&[iface]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "*1");
        assert_eq!(result[0].name, "ether1");
        assert_eq!(result[0].rx_bytes, 0);
        assert_eq!(result[0].tx_bytes, 0);
        assert!(!result[0].running);
    }

    #[test]
    fn test_parse_interfaces_filters_peers() {
        let mut peer = HashMap::new();
        peer.insert("name".to_string(), "unnamed-peer".to_string());
        peer.insert("interface".to_string(), "wg1".to_string());
        peer.insert("public-key".to_string(), "abc".to_string());

        let result = parse_interfaces(&[peer]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_interfaces_no_type() {
        let mut iface = HashMap::new();
        iface.insert(".id".to_string(), "*1".to_string());
        iface.insert("name".to_string(), "ether1".to_string());

        let result = parse_interfaces(&[iface]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "*1");
        assert_eq!(result[0].name, "ether1");
        assert_eq!(result[0].rx_bytes, 0);
        assert_eq!(result[0].tx_bytes, 0);
        assert!(!result[0].running);
    }

    #[test]
    fn test_parse_interfaces_empty() {
        let result = parse_interfaces(&[]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_interfaces_no_name() {
        let mut data = HashMap::new();
        data.insert("rx-byte".to_string(), "1000".to_string());

        let result = parse_interfaces(&[data]);
        assert_eq!(result.len(), 0);
    }
}
