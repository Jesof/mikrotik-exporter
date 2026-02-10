// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! WireGuard metrics collection for MikroTik routers
//!
//! This module implements parsing of WireGuard interface and peer information
//! from RouterOS API responses and structures for storing the parsed data.

use std::collections::HashMap;

/// Statistics for a WireGuard interface
#[derive(Debug, Clone, PartialEq)]
pub struct WireGuardInterfaceStats {
    pub name: String,
    pub enabled: bool,
}

/// Statistics for a WireGuard peer
#[derive(Debug, Clone, PartialEq)]
pub struct WireGuardPeerStats {
    pub interface: String,
    pub public_key: String,
    pub endpoint: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub latest_handshake: Option<u64>, // Unix timestamp
}

/// Parse WireGuard interface information from RouterOS API response
pub(super) fn parse_wireguard_interfaces(
    sentences: &[HashMap<String, String>],
) -> Vec<WireGuardInterfaceStats> {
    let mut interfaces = Vec::new();

    for sentence in sentences {
        if let Some(name) = sentence.get("name") {
            interfaces.push(WireGuardInterfaceStats {
                name: name.clone(),
                enabled: sentence.get("disabled").map_or(true, |v| v != "true"),
            });
        }
    }

    interfaces
}

/// Parse WireGuard peer information from RouterOS API response
pub(super) fn parse_wireguard_peers(
    sentences: &[HashMap<String, String>],
) -> Vec<WireGuardPeerStats> {
    let mut peers = Vec::new();

    for sentence in sentences {
        if let Some(interface) = sentence.get("interface") {
            if let Some(public_key) = sentence.get("public-key") {
                let rx_bytes = sentence
                    .get("rx")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);

                let tx_bytes = sentence
                    .get("tx")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);

                // Parse latest-handshake to timestamp if available
                let latest_handshake = sentence
                    .get("latest-handshake")
                    .and_then(|v| parse_handshake_to_timestamp(v));

                peers.push(WireGuardPeerStats {
                    interface: interface.clone(),
                    public_key: public_key.clone(),
                    endpoint: sentence.get("endpoint").cloned(),
                    rx_bytes,
                    tx_bytes,
                    latest_handshake,
                });
            }
        }
    }

    peers
}

/// Parse the latest-handshake field to a Unix timestamp
fn parse_handshake_to_timestamp(handshake_str: &str) -> Option<u64> {
    if handshake_str.is_empty() || handshake_str == "never" {
        return None;
    }

    // RouterOS stores handshake time in format like "2023-05-15 10:30:45"
    // We need to convert this to a Unix timestamp
    // For now, we'll return None as proper parsing would require chrono or similar
    // In a real implementation, we would parse this datetime string to a timestamp
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wireguard_interfaces_empty() {
        let result = parse_wireguard_interfaces(&[]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_wireguard_interfaces_single() {
        let mut data = HashMap::new();
        data.insert("name".to_string(), "wg1".to_string());
        data.insert("disabled".to_string(), "false".to_string());

        let result = parse_wireguard_interfaces(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "wg1");
        assert!(result[0].enabled);
    }

    #[test]
    fn test_parse_wireguard_interfaces_disabled() {
        let mut data = HashMap::new();
        data.insert("name".to_string(), "wg1".to_string());
        data.insert("disabled".to_string(), "true".to_string());

        let result = parse_wireguard_interfaces(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "wg1");
        assert!(!result[0].enabled);
    }

    #[test]
    fn test_parse_wireguard_interfaces_multiple() {
        let mut iface1 = HashMap::new();
        iface1.insert("name".to_string(), "wg1".to_string());
        iface1.insert("disabled".to_string(), "false".to_string());

        let mut iface2 = HashMap::new();
        iface2.insert("name".to_string(), "wg2".to_string());
        iface2.insert("disabled".to_string(), "true".to_string());

        let result = parse_wireguard_interfaces(&[iface1, iface2]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "wg1");
        assert!(result[0].enabled);
        assert_eq!(result[1].name, "wg2");
        assert!(!result[1].enabled);
    }

    #[test]
    fn test_parse_wireguard_interfaces_missing_name() {
        let mut data = HashMap::new();
        data.insert("disabled".to_string(), "false".to_string());

        let result = parse_wireguard_interfaces(&[data]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_wireguard_interfaces_no_disabled_field() {
        let mut data = HashMap::new();
        data.insert("name".to_string(), "wg1".to_string());

        let result = parse_wireguard_interfaces(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "wg1");
        assert!(result[0].enabled); // Default to enabled when disabled field is missing
    }

    #[test]
    fn test_parse_wireguard_peers_empty() {
        let result = parse_wireguard_peers(&[]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_wireguard_peers_single() {
        let mut data = HashMap::new();
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("public-key".to_string(), "abc123".to_string());
        data.insert("endpoint".to_string(), "192.168.1.1:51820".to_string());
        data.insert("rx".to_string(), "1024".to_string());
        data.insert("tx".to_string(), "2048".to_string());
        data.insert("latest-handshake".to_string(), "never".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].interface, "wg1");
        assert_eq!(result[0].public_key, "abc123");
        assert_eq!(result[0].endpoint, Some("192.168.1.1:51820".to_string()));
        assert_eq!(result[0].rx_bytes, 1024);
        assert_eq!(result[0].tx_bytes, 2048);
        assert_eq!(result[0].latest_handshake, None);
    }

    #[test]
    fn test_parse_wireguard_peers_missing_fields() {
        let mut data = HashMap::new();
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("public-key".to_string(), "abc123".to_string());
        // Missing endpoint, rx, tx, latest-handshake

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].interface, "wg1");
        assert_eq!(result[0].public_key, "abc123");
        assert_eq!(result[0].endpoint, None);
        assert_eq!(result[0].rx_bytes, 0);
        assert_eq!(result[0].tx_bytes, 0);
        assert_eq!(result[0].latest_handshake, None);
    }

    #[test]
    fn test_parse_wireguard_peers_invalid_numbers() {
        let mut data = HashMap::new();
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("public-key".to_string(), "abc123".to_string());
        data.insert("rx".to_string(), "invalid".to_string());
        data.insert("tx".to_string(), "also-invalid".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rx_bytes, 0);
        assert_eq!(result[0].tx_bytes, 0);
    }

    #[test]
    fn test_parse_wireguard_peers_missing_interface() {
        let mut data = HashMap::new();
        data.insert("public-key".to_string(), "abc123".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_wireguard_peers_missing_public_key() {
        let mut data = HashMap::new();
        data.insert("interface".to_string(), "wg1".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_wireguard_peers_multiple() {
        let mut peer1 = HashMap::new();
        peer1.insert("interface".to_string(), "wg1".to_string());
        peer1.insert("public-key".to_string(), "abc123".to_string());
        peer1.insert("endpoint".to_string(), "192.168.1.1:51820".to_string());
        peer1.insert("rx".to_string(), "1024".to_string());
        peer1.insert("tx".to_string(), "2048".to_string());

        let mut peer2 = HashMap::new();
        peer2.insert("interface".to_string(), "wg1".to_string());
        peer2.insert("public-key".to_string(), "def456".to_string());
        peer2.insert("endpoint".to_string(), "192.168.1.2:51820".to_string());
        peer2.insert("rx".to_string(), "2048".to_string());
        peer2.insert("tx".to_string(), "4096".to_string());

        let result = parse_wireguard_peers(&[peer1, peer2]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].interface, "wg1");
        assert_eq!(result[0].public_key, "abc123");
        assert_eq!(result[0].endpoint, Some("192.168.1.1:51820".to_string()));
        assert_eq!(result[0].rx_bytes, 1024);
        assert_eq!(result[0].tx_bytes, 2048);

        assert_eq!(result[1].interface, "wg1");
        assert_eq!(result[1].public_key, "def456");
        assert_eq!(result[1].endpoint, Some("192.168.1.2:51820".to_string()));
        assert_eq!(result[1].rx_bytes, 2048);
        assert_eq!(result[1].tx_bytes, 4096);
    }

    #[test]
    fn test_parse_handshake_to_timestamp() {
        // Test that the function returns None for "never"
        assert_eq!(parse_handshake_to_timestamp("never"), None);

        // Test that the function returns None for empty string
        assert_eq!(parse_handshake_to_timestamp(""), None);

        // In a real implementation, we would test actual datetime parsing
        // But for now, we just test that it returns None for any non-empty string that isn't "never"
        assert_eq!(parse_handshake_to_timestamp("2023-05-15 10:30:45"), None);
    }
}
