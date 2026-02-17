// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Interface parsing

use crate::mikrotik::types::InterfaceStats;
use std::collections::HashMap;

pub(crate) fn parse_interfaces(sentences: &[HashMap<String, String>]) -> Vec<InterfaceStats> {
    let mut out = Vec::new();
    for s in sentences {
        if let (Some(name), Some(_type)) = (s.get("name"), s.get("type")) {
            out.push(InterfaceStats {
                name: name.clone(),
                rx_bytes: s.get("rx-byte").and_then(|v| v.parse().ok()).unwrap_or(0),
                tx_bytes: s.get("tx-byte").and_then(|v| v.parse().ok()).unwrap_or(0),
                rx_packets: s.get("rx-packet").and_then(|v| v.parse().ok()).unwrap_or(0),
                tx_packets: s.get("tx-packet").and_then(|v| v.parse().ok()).unwrap_or(0),
                rx_errors: s.get("rx-error").and_then(|v| v.parse().ok()).unwrap_or(0),
                tx_errors: s.get("tx-error").and_then(|v| v.parse().ok()).unwrap_or(0),
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
        iface1.insert("name".to_string(), "ether1".to_string());
        iface1.insert("type".to_string(), "ether".to_string());
        iface1.insert("rx-byte".to_string(), "1000".to_string());
        iface1.insert("tx-byte".to_string(), "2000".to_string());
        iface1.insert("rx-packet".to_string(), "10".to_string());
        iface1.insert("tx-packet".to_string(), "20".to_string());
        iface1.insert("rx-error".to_string(), "0".to_string());
        iface1.insert("tx-error".to_string(), "0".to_string());
        iface1.insert("running".to_string(), "true".to_string());

        let result = parse_interfaces(&[iface1]);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "ether1");
        assert_eq!(result[0].rx_bytes, 1000);
        assert_eq!(result[0].tx_bytes, 2000);
        assert!(result[0].running);
    }

    #[test]
    fn test_parse_interfaces_multiple() {
        let mut iface1 = HashMap::new();
        iface1.insert("name".to_string(), "ether1".to_string());
        iface1.insert("type".to_string(), "ether".to_string());
        iface1.insert("running".to_string(), "true".to_string());

        let mut iface2 = HashMap::new();
        iface2.insert("name".to_string(), "ether2".to_string());
        iface2.insert("type".to_string(), "ether".to_string());
        iface2.insert("running".to_string(), "false".to_string());

        let result = parse_interfaces(&[iface1, iface2]);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "ether1");
        assert!(result[0].running);
        assert_eq!(result[1].name, "ether2");
        assert!(!result[1].running);
    }

    #[test]
    fn test_parse_interfaces_missing_values() {
        let mut iface = HashMap::new();
        iface.insert("name".to_string(), "ether1".to_string());
        iface.insert("type".to_string(), "ether".to_string());

        let result = parse_interfaces(&[iface]);

        assert_eq!(result.len(), 1);
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
        iface.insert("name".to_string(), "ether1".to_string());

        let result = parse_interfaces(&[iface]);
        assert_eq!(result.len(), 0);
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
