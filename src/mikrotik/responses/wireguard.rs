// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! WireGuard metrics collection for MikroTik routers
//!
//! This module implements parsing of WireGuard interface and peer information
//! from RouterOS API responses and structures for storing the parsed data.
//!
//! For peer identification, we use `.id` as the primary key.

use crate::mikrotik::types::WireGuardPeerStats;
use std::collections::HashMap;
use std::time::SystemTime;

/// Parse WireGuard peer information from RouterOS API response
pub(crate) fn parse_wireguard_peers(
    sentences: &[HashMap<String, String>],
) -> Vec<WireGuardPeerStats> {
    let mut peers = Vec::new();

    for sentence in sentences {
        if sentence
            .get("disabled")
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        {
            continue;
        }

        if let (Some(id), Some(interface)) = (sentence.get(".id"), sentence.get("interface")) {
            let rx_bytes = sentence
                .get("rx")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            let tx_bytes = sentence
                .get("tx")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);

            let latest_handshake =
                get_field_value(sentence, &["last-handshake", "latest-handshake"])
                    .and_then(|v| parse_handshake_to_timestamp(&v));

            if let Some(allowed_address) = sentence.get("allowed-address") {
                peers.push(WireGuardPeerStats {
                    id: id.clone(),
                    interface: interface.clone(),
                    name: sentence
                        .get("name")
                        .cloned()
                        .unwrap_or_else(|| "unnamed-peer".to_string()),
                    comment: sentence.get("comment").cloned().unwrap_or_default(),
                    allowed_address: allowed_address.clone(),
                    endpoint: parse_peer_endpoint(sentence),
                    rx_bytes,
                    tx_bytes,
                    latest_handshake,
                });
            }
        }
    }

    peers
}

fn get_field_value(fields: &HashMap<String, String>, possible_names: &[&str]) -> Option<String> {
    possible_names
        .iter()
        .find_map(|name| fields.get(*name).cloned())
}

fn parse_peer_endpoint(fields: &HashMap<String, String>) -> Option<String> {
    let address = get_field_value(fields, &["current-endpoint-address", "endpoint"])?;
    if address.is_empty() {
        return None;
    }
    Some(address)
}

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

fn parse_routeros_duration(duration_str: &str) -> Option<u64> {
    if duration_str.is_empty() {
        return Some(0);
    }

    let mut total_seconds: u64 = 0;
    let mut current_number = 0u64;

    for ch in duration_str.chars() {
        match ch {
            '0'..='9' => {
                if let Some(new_val) = current_number
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((ch as u8 - b'0') as u64))
                {
                    current_number = new_val;
                } else {
                    return Some(u64::MAX);
                }
            }
            's' => {
                total_seconds = total_seconds.saturating_add(current_number);
                current_number = 0;
            }
            'm' => {
                total_seconds = total_seconds.saturating_add(current_number.saturating_mul(60));
                current_number = 0;
            }
            'h' => {
                total_seconds = total_seconds.saturating_add(current_number.saturating_mul(3600));
                current_number = 0;
            }
            'd' => {
                total_seconds = total_seconds.saturating_add(current_number.saturating_mul(86400));
                current_number = 0;
            }
            'w' => {
                total_seconds = total_seconds.saturating_add(current_number.saturating_mul(604800));
                current_number = 0;
            }
            _ => {
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
    fn test_parse_wireguard_peers_empty() {
        let result = parse_wireguard_peers(&[]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_wireguard_peers_single() {
        let mut data = HashMap::new();
        data.insert(".id".to_string(), "*1".to_string());
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("name".to_string(), "peer1".to_string());
        data.insert("comment".to_string(), "John".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());
        data.insert(
            "current-endpoint-address".to_string(),
            "192.168.1.1".to_string(),
        );
        data.insert("rx".to_string(), "1024".to_string());
        data.insert("tx".to_string(), "2048".to_string());
        data.insert("last-handshake".to_string(), "never".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "*1");
        assert_eq!(result[0].interface, "wg1");
        assert_eq!(result[0].name, "peer1");
        assert_eq!(result[0].comment, "John");
        assert_eq!(result[0].allowed_address, "10.10.10.1/32");
        assert_eq!(result[0].endpoint, Some("192.168.1.1".to_string()));
        assert_eq!(result[0].rx_bytes, 1024);
        assert_eq!(result[0].tx_bytes, 2048);
        assert_eq!(result[0].latest_handshake, None);
    }

    #[test]
    fn test_parse_wireguard_peers_with_handshake() {
        let mut data = HashMap::new();
        data.insert(".id".to_string(), "*1".to_string());
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("name".to_string(), "peer1".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());
        data.insert(
            "current-endpoint-address".to_string(),
            "192.168.1.1".to_string(),
        );
        data.insert("rx".to_string(), "1024".to_string());
        data.insert("tx".to_string(), "2048".to_string());
        data.insert("last-handshake".to_string(), "120".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "*1");
        assert_eq!(result[0].interface, "wg1");
        assert_eq!(result[0].name, "peer1");
        assert_eq!(result[0].allowed_address, "10.10.10.1/32");
        assert_eq!(result[0].endpoint, Some("192.168.1.1".to_string()));
        assert_eq!(result[0].rx_bytes, 1024);
        assert_eq!(result[0].tx_bytes, 2048);
        assert!(result[0].latest_handshake.is_some());
    }

    #[test]
    fn test_parse_wireguard_peers_missing_fields() {
        let mut data = HashMap::new();
        data.insert(".id".to_string(), "*1".to_string());
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("name".to_string(), "peer1".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "*1");
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
        data.insert(".id".to_string(), "*1".to_string());
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "*1");
        assert_eq!(result[0].interface, "wg1");
        assert_eq!(result[0].name, "unnamed-peer");
        assert_eq!(result[0].comment, "");
        assert_eq!(result[0].allowed_address, "10.10.10.1/32");
    }

    #[test]
    fn test_parse_wireguard_peers_invalid_numbers() {
        let mut data = HashMap::new();
        data.insert(".id".to_string(), "*1".to_string());
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
        data.insert(".id".to_string(), "*1".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_wireguard_peers_missing_allowed_address() {
        let mut data = HashMap::new();
        data.insert(".id".to_string(), "*1".to_string());
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("name".to_string(), "peer1".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_wireguard_peers_multiple() {
        let mut peer1 = HashMap::new();
        peer1.insert(".id".to_string(), "*1".to_string());
        peer1.insert("interface".to_string(), "wg1".to_string());
        peer1.insert("name".to_string(), "peer1".to_string());
        peer1.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());
        peer1.insert(
            "current-endpoint-address".to_string(),
            "192.168.1.1".to_string(),
        );
        peer1.insert("rx".to_string(), "1024".to_string());
        peer1.insert("tx".to_string(), "2048".to_string());

        let mut peer2 = HashMap::new();
        peer2.insert(".id".to_string(), "*2".to_string());
        peer2.insert("interface".to_string(), "wg1".to_string());
        peer2.insert("name".to_string(), "peer2".to_string());
        peer2.insert("allowed-address".to_string(), "10.10.10.2/32".to_string());
        peer2.insert(
            "current-endpoint-address".to_string(),
            "192.168.1.2".to_string(),
        );
        peer2.insert("rx".to_string(), "2048".to_string());
        peer2.insert("tx".to_string(), "4096".to_string());

        let result = parse_wireguard_peers(&[peer1, peer2]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "peer1");
        assert_eq!(result[1].name, "peer2");
    }

    #[test]
    fn test_parse_wireguard_peers_disabled() {
        let mut data = HashMap::new();
        data.insert(".id".to_string(), "*1".to_string());
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("name".to_string(), "peer1".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());
        data.insert("disabled".to_string(), "true".to_string());

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_wireguard_peers_current_endpoint_only() {
        let mut data = HashMap::new();
        data.insert(".id".to_string(), "*1".to_string());
        data.insert("interface".to_string(), "wg1".to_string());
        data.insert("allowed-address".to_string(), "10.10.10.1/32".to_string());
        data.insert(
            "current-endpoint-address".to_string(),
            "2001:db8::1".to_string(),
        );

        let result = parse_wireguard_peers(&[data]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].endpoint, Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_parse_handshake_to_timestamp() {
        assert_eq!(parse_handshake_to_timestamp("never"), None);
        assert_eq!(parse_handshake_to_timestamp(""), None);

        let ts120 = parse_handshake_to_timestamp("120");
        assert!(ts120.is_some());
    }

    #[test]
    fn test_parse_routeros_duration() {
        assert_eq!(parse_routeros_duration("7s"), Some(7));
        assert_eq!(parse_routeros_duration("1m30s"), Some(90));
        assert_eq!(parse_routeros_duration("2h30m"), Some(9000));
        assert_eq!(parse_routeros_duration("1d2h"), Some(93600));
        assert_eq!(parse_routeros_duration("1w2d"), Some(777600));
        assert_eq!(parse_routeros_duration(""), Some(0));
        assert_eq!(parse_routeros_duration("0s"), Some(0));
    }

    #[test]
    fn test_get_field_value() {
        let mut data = HashMap::new();
        data.insert("last-handshake".to_string(), "120".to_string());

        assert_eq!(
            get_field_value(&data, &["last-handshake"]),
            Some("120".to_string())
        );
        assert_eq!(
            get_field_value(&data, &["latest-handshake", "last-handshake"]),
            Some("120".to_string())
        );
        assert_eq!(get_field_value(&data, &["nonexistent"]), None);
    }

    #[test]
    fn test_parse_routeros_duration_overflow_protection() {
        assert_eq!(
            parse_routeros_duration("9999999999999999999999999999999999999999s"),
            Some(u64::MAX)
        );
    }
}
