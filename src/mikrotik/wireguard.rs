// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! WireGuard metrics collection for MikroTik routers
//!
//! This module implements parsing of WireGuard interface and peer information
//! from RouterOS API responses and structures for storing the parsed data.
//!
//! For peer identification, we use `allowed-address` instead of `public-key`
//! to avoid collecting sensitive information. This approach provides a stable
//! identifier for monitoring while maintaining privacy.

use std::collections::HashMap;
use std::time::SystemTime;

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
    pub name: String,
    pub allowed_address: String,
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
                enabled: sentence.get("disabled").is_none_or(|v| v != "true"),
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
            let rx_bytes = sentence
                .get("rx")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            let tx_bytes = sentence
                .get("tx")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            // Parse last-handshake to timestamp if available
            // Support both "last-handshake" (new) and "latest-handshake" (old) field names
            let latest_handshake =
                get_field_value(sentence, &["last-handshake", "latest-handshake"])
                    .and_then(|v| parse_handshake_to_timestamp(&v));

            // Use allowed-address as the identifier instead of public-key
            if let Some(allowed_address) = sentence.get("allowed-address") {
                peers.push(WireGuardPeerStats {
                    interface: interface.clone(),
                    name: sentence
                        .get("name")
                        .cloned()
                        .unwrap_or_else(|| "unnamed-peer".to_string()),
                    allowed_address: allowed_address.clone(),
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

/// Get field value with fallback support for different field names
///
/// This function tries to get a field value from a HashMap, supporting multiple
/// possible field names for backward compatibility with different RouterOS versions.
fn get_field_value(fields: &HashMap<String, String>, possible_names: &[&str]) -> Option<String> {
    possible_names
        .iter()
        .find_map(|name| fields.get(*name).cloned())
}

/// Parse the last-handshake field from RouterOS duration format to seconds
///
/// The RouterOS API returns the last-handshake field in duration format like:
/// - "7s" (7 seconds)
/// - "1w4d9h15m7s" (1 week, 4 days, 9 hours, 15 minutes, 7 seconds)
/// - "never" (no handshake)
/// - "120" (120 seconds, older RouterOS versions)
/// - "0s" or "" (zero seconds)
///
/// Returns the total seconds as a u64, or None if the handshake was never.
/// See: https://help.mikrotik.com/docs/spaces/ROS/pages/69664792/WireGuard
fn parse_handshake_to_timestamp(handshake_str: &str) -> Option<u64> {
    if handshake_str.is_empty() || handshake_str == "never" {
        return None;
    }

    let duration_secs = if let Ok(seconds) = handshake_str.parse::<u64>() {
        seconds
    } else {
        parse_routeros_duration(handshake_str)?
    };

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();

    Some(now.saturating_sub(duration_secs))
}

/// Parse RouterOS duration format to seconds
///
/// RouterOS uses a format like "1w4d9h15m7s" meaning:
/// - w = weeks (1w = 7 days)
/// - d = days
/// - h = hours
/// - m = minutes
/// - s = seconds
fn parse_routeros_duration(duration_str: &str) -> Option<u64> {
    if duration_str.is_empty() {
        return Some(0);
    }

    let mut total_seconds: u64 = 0;
    let mut current_number = 0u64;

    for ch in duration_str.chars() {
        match ch {
            '0'..='9' => {
                // Parse digit and check for overflow
                if let Some(new_val) = current_number
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((ch as u8 - b'0') as u64))
                {
                    current_number = new_val;
                } else {
                    // If overflow occurs during number parsing, return maximum value
                    return Some(u64::MAX);
                }
            }
            's' => {
                // Add seconds with overflow protection
                total_seconds = total_seconds.saturating_add(current_number);
                current_number = 0;
            }
            'm' => {
                // Add minutes (60 seconds) with overflow protection
                total_seconds = total_seconds.saturating_add(current_number.saturating_mul(60));
                current_number = 0;
            }
            'h' => {
                // Add hours (3600 seconds) with overflow protection
                total_seconds = total_seconds.saturating_add(current_number.saturating_mul(3600));
                current_number = 0;
            }
            'd' => {
                // Add days (86400 seconds) with overflow protection
                total_seconds = total_seconds.saturating_add(current_number.saturating_mul(86400));
                current_number = 0;
            }
            'w' => {
                // Add weeks (604800 seconds) with overflow protection
                total_seconds = total_seconds.saturating_add(current_number.saturating_mul(604800)); // 7 days in a week
                current_number = 0;
            }
            _ => {
                // Ignore any other characters
                continue;
            }
        }
    }

    Some(total_seconds)
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
        data.insert("name".to_string(), "peer1".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());
        data.insert("endpoint".to_string(), "192.168.1.1:51820".to_string());
        data.insert("rx".to_string(), "1024".to_string());
        data.insert("tx".to_string(), "2048".to_string());
        data.insert("last-handshake".to_string(), "never".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].interface, "wg1");
        assert_eq!(result[0].name, "peer1");
        assert_eq!(result[0].allowed_address, "10.10.10.1/32");
        assert_eq!(result[0].endpoint, Some("192.168.1.1:51820".to_string()));
        assert_eq!(result[0].rx_bytes, 1024);
        assert_eq!(result[0].tx_bytes, 2048);
        assert_eq!(result[0].latest_handshake, None);
    }

    #[test]
    fn test_parse_wireguard_peers_with_handshake() {
        let mut data = HashMap::new();
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("name".to_string(), "peer1".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());
        data.insert("endpoint".to_string(), "192.168.1.1:51820".to_string());
        data.insert("rx".to_string(), "1024".to_string());
        data.insert("tx".to_string(), "2048".to_string());
        data.insert("last-handshake".to_string(), "120".to_string()); // 120 seconds since last handshake

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].interface, "wg1");
        assert_eq!(result[0].name, "peer1");
        assert_eq!(result[0].allowed_address, "10.10.10.1/32");
        assert_eq!(result[0].endpoint, Some("192.168.1.1:51820".to_string()));
        assert_eq!(result[0].rx_bytes, 1024);
        assert_eq!(result[0].tx_bytes, 2048);
        assert!(result[0].latest_handshake.is_some());
        let handshake = result[0].latest_handshake.unwrap();
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(handshake <= now);
        assert!(handshake >= now - 130); // account for test execution time
    }

    #[test]
    fn test_parse_wireguard_peers_missing_fields() {
        let mut data = HashMap::new();
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("name".to_string(), "peer1".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());
        // Missing endpoint, rx, tx, last-handshake

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].interface, "wg1");
        assert_eq!(result[0].name, "peer1");
        assert_eq!(result[0].allowed_address, "10.10.10.1/32");
        assert_eq!(result[0].endpoint, None);
        assert_eq!(result[0].rx_bytes, 0);
        assert_eq!(result[0].tx_bytes, 0);
        assert_eq!(result[0].latest_handshake, None);
    }

    #[test]
    fn test_parse_wireguard_peers_missing_name_field() {
        let mut data = HashMap::new();
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());
        // Missing name field

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].interface, "wg1");
        assert_eq!(result[0].name, "unnamed-peer"); // Should use default name
        assert_eq!(result[0].allowed_address, "10.10.10.1/32");
        assert_eq!(result[0].endpoint, None);
        assert_eq!(result[0].rx_bytes, 0);
        assert_eq!(result[0].tx_bytes, 0);
        assert_eq!(result[0].latest_handshake, None);
    }

    #[test]
    fn test_parse_wireguard_peers_invalid_numbers() {
        let mut data = HashMap::new();
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("name".to_string(), "peer1".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());
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
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_wireguard_peers_missing_allowed_address() {
        let mut data = HashMap::new();
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("name".to_string(), "peer1".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_wireguard_peers_multiple() {
        let mut peer1 = HashMap::new();
        peer1.insert("interface".to_string(), "wg1".to_string());
        peer1.insert("name".to_string(), "peer1".to_string());
        peer1.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());
        peer1.insert("endpoint".to_string(), "192.168.1.1:51820".to_string());
        peer1.insert("rx".to_string(), "1024".to_string());
        peer1.insert("tx".to_string(), "2048".to_string());

        let mut peer2 = HashMap::new();
        peer2.insert("interface".to_string(), "wg1".to_string());
        peer2.insert("name".to_string(), "peer2".to_string());
        peer2.insert("allowed-address".to_string(), "10.10.10.2/32".to_string());
        peer2.insert("endpoint".to_string(), "192.168.1.2:51820".to_string());
        peer2.insert("rx".to_string(), "2048".to_string());
        peer2.insert("tx".to_string(), "4096".to_string());

        let result = parse_wireguard_peers(&[peer1, peer2]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].interface, "wg1");
        assert_eq!(result[0].name, "peer1");
        assert_eq!(result[0].allowed_address, "10.10.10.1/32");
        assert_eq!(result[0].endpoint, Some("192.168.1.1:51820".to_string()));
        assert_eq!(result[0].rx_bytes, 1024);
        assert_eq!(result[0].tx_bytes, 2048);

        assert_eq!(result[1].interface, "wg1");
        assert_eq!(result[1].name, "peer2");
        assert_eq!(result[1].allowed_address, "10.10.10.2/32");
        assert_eq!(result[1].endpoint, Some("192.168.1.2:51820".to_string()));
        assert_eq!(result[1].rx_bytes, 2048);
        assert_eq!(result[1].tx_bytes, 4096);
    }

    #[test]
    fn test_parse_handshake_to_timestamp() {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Test that the function returns None for "never"
        assert_eq!(parse_handshake_to_timestamp("never"), None);

        // Test that the function returns None for empty string
        assert_eq!(parse_handshake_to_timestamp(""), None);

        // Test that the function correctly parses plain integer values (backward compatibility)
        let ts0 = parse_handshake_to_timestamp("0").unwrap();
        assert!(ts0 <= now && ts0 >= now - 2);

        let ts120 = parse_handshake_to_timestamp("120").unwrap();
        assert!(ts120 <= now - 120 && ts120 >= now - 122);

        // Test that the function correctly parses RouterOS duration format
        let ts7s = parse_handshake_to_timestamp("7s").unwrap();
        assert!(ts7s <= now - 7 && ts7s >= now - 9);

        let ts90s = parse_handshake_to_timestamp("1m30s").unwrap();
        assert!(ts90s <= now - 90 && ts90s >= now - 92);

        // Test zero duration
        let ts0s = parse_handshake_to_timestamp("0s").unwrap();
        assert!(ts0s <= now && ts0s >= now - 2);
    }

    #[test]
    fn test_parse_routeros_duration() {
        // Test the helper function directly
        assert_eq!(parse_routeros_duration("7s"), Some(7));
        assert_eq!(parse_routeros_duration("1m30s"), Some(90));
        assert_eq!(parse_routeros_duration("2h30m"), Some(9000));
        assert_eq!(parse_routeros_duration("1d2h"), Some(93600));
        assert_eq!(parse_routeros_duration("1w2d"), Some(777600));
        assert_eq!(parse_routeros_duration("1w4d9h15m7s"), Some(983707)); // Correct calculation
        assert_eq!(parse_routeros_duration(""), Some(0));
        assert_eq!(parse_routeros_duration("0s"), Some(0));
    }

    #[test]
    fn test_get_field_value() {
        let mut data = HashMap::new();
        data.insert("last-handshake".to_string(), "120".to_string());

        // Test exact match
        assert_eq!(
            get_field_value(&data, &["last-handshake"]),
            Some("120".to_string())
        );

        // Test fallback to second option
        assert_eq!(
            get_field_value(&data, &["latest-handshake", "last-handshake"]),
            Some("120".to_string())
        );

        // Test no match
        assert_eq!(get_field_value(&data, &["nonexistent"]), None);
    }

    #[test]
    fn test_parse_routeros_duration_overflow_protection() {
        // Test with a very large number that could cause overflow
        // This should safely saturate rather than panic
        assert_eq!(
            parse_routeros_duration("9999999999999999999999999999999999999999s"),
            Some(u64::MAX)
        );
    }
}
