// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! RouterOS response parsing helpers

use crate::mikrotik::types::{ConnectionTrackingStats, InterfaceStats, SystemResource};
use std::collections::HashMap;

pub(crate) fn parse_system(sentences: &[HashMap<String, String>]) -> SystemResource {
    let first_opt = sentences.iter().find(|s| s.contains_key("version"));
    let empty = HashMap::new();
    let first = first_opt.unwrap_or(&empty);
    SystemResource {
        uptime: first
            .get("uptime")
            .cloned()
            .unwrap_or_else(|| "0s".to_string()),
        cpu_load: first
            .get("cpu-load")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        free_memory: first
            .get("free-memory")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        total_memory: first
            .get("total-memory")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        version: first
            .get("version")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        board_name: first
            .get("board-name")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
    }
}

pub(crate) fn parse_interfaces(sentences: &[HashMap<String, String>]) -> Vec<InterfaceStats> {
    let mut out = Vec::new();
    for s in sentences {
        if let Some(name) = s.get("name") {
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

/// Parse connection tracking entries and aggregate by source address and protocol
pub(crate) fn parse_connection_tracking(
    sentences: &[HashMap<String, String>],
    ip_version: &str,
) -> Vec<ConnectionTrackingStats> {
    use std::collections::HashMap;

    // Aggregate connections by (src_address, protocol)
    let mut aggregated: HashMap<(String, String), u64> = HashMap::new();

    for s in sentences {
        if let Some(src) = s.get("src-address") {
            let src_ip = extract_src_ip(src);
            let protocol = s
                .get("protocol")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let key = (src_ip, protocol);
            *aggregated.entry(key).or_insert(0) += 1;
        }
    }

    // Convert to Vec<ConnectionTrackingStats>
    aggregated
        .into_iter()
        .map(|((src_address, protocol), count)| ConnectionTrackingStats {
            src_address,
            protocol,
            connection_count: count,
            ip_version: ip_version.to_string(),
        })
        .collect()
}

/// Extract the source IP address from a RouterOS connection tracking entry.
///
/// Handles IPv4 with port (`192.168.1.1:12345`), IPv6 with brackets
/// (`[::1]:12345`), and bare IPs without ports.
#[must_use]
fn extract_src_ip(src: &str) -> String {
    if let Ok(socket) = src.parse::<std::net::SocketAddr>() {
        return socket.ip().to_string();
    }

    if let Some(stripped) = src.strip_prefix('[') {
        if let Some((ip, _port)) = stripped.split_once(":]") {
            return ip.to_string();
        }
        if let Some((ip, _rest)) = stripped.split_once(']') {
            return ip.to_string();
        }
    }

    if let Some((ip, _port)) = src.rsplit_once(':') {
        if ip.parse::<std::net::IpAddr>().is_ok() || ip.contains('.') {
            return ip.to_string();
        }
    }

    src.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_system_complete() {
        let mut data = HashMap::new();
        data.insert("version".to_string(), "7.10".to_string());
        data.insert("uptime".to_string(), "1w2d3h4m5s".to_string());
        data.insert("cpu-load".to_string(), "25".to_string());
        data.insert("free-memory".to_string(), "524288000".to_string());
        data.insert("total-memory".to_string(), "1073741824".to_string());
        data.insert("board-name".to_string(), "RB750Gr3".to_string());

        let result = parse_system(&[data]);

        assert_eq!(result.version, "7.10");
        assert_eq!(result.uptime, "1w2d3h4m5s");
        assert_eq!(result.cpu_load, 25);
        assert_eq!(result.free_memory, 524288000);
        assert_eq!(result.total_memory, 1073741824);
        assert_eq!(result.board_name, "RB750Gr3");
    }

    #[test]
    fn test_parse_system_empty() {
        let result = parse_system(&[]);
        assert_eq!(result.version, "unknown");
        assert_eq!(result.uptime, "0s");
        assert_eq!(result.cpu_load, 0);
        assert_eq!(result.board_name, "unknown");
    }

    #[test]
    fn test_parse_system_partial() {
        let mut data = HashMap::new();
        data.insert("version".to_string(), "7.10".to_string());

        let result = parse_system(&[data]);

        assert_eq!(result.version, "7.10");
        assert_eq!(result.uptime, "0s");
        assert_eq!(result.cpu_load, 0);
    }

    #[test]
    fn test_parse_interfaces_complete() {
        let mut iface1 = HashMap::new();
        iface1.insert("name".to_string(), "ether1".to_string());
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
        iface1.insert("running".to_string(), "true".to_string());

        let mut iface2 = HashMap::new();
        iface2.insert("name".to_string(), "ether2".to_string());
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

        let result = parse_interfaces(&[iface]);

        assert_eq!(result.len(), 1);
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

    #[test]
    fn test_parse_connection_tracking_empty() {
        let result = parse_connection_tracking(&[], "ipv4");
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_connection_tracking_single() {
        let mut conn = HashMap::new();
        conn.insert("src-address".to_string(), "192.168.1.100:12345".to_string());
        conn.insert("dst-address".to_string(), "8.8.8.8:53".to_string());
        conn.insert("protocol".to_string(), "udp".to_string());

        let result = parse_connection_tracking(&[conn], "ipv4");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src_address, "192.168.1.100");
        assert_eq!(result[0].protocol, "udp");
        assert_eq!(result[0].connection_count, 1);
        assert_eq!(result[0].ip_version, "ipv4");
    }

    #[test]
    fn test_parse_connection_tracking_aggregate_same_source() {
        let mut conn1 = HashMap::new();
        conn1.insert("src-address".to_string(), "192.168.1.100:12345".to_string());
        conn1.insert("protocol".to_string(), "tcp".to_string());

        let mut conn2 = HashMap::new();
        conn2.insert("src-address".to_string(), "192.168.1.100:12346".to_string());
        conn2.insert("protocol".to_string(), "tcp".to_string());

        let result = parse_connection_tracking(&[conn1, conn2], "ipv4");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src_address, "192.168.1.100");
        assert_eq!(result[0].protocol, "tcp");
        assert_eq!(result[0].connection_count, 2);
    }

    #[test]
    fn test_parse_connection_tracking_different_protocols() {
        let mut tcp_conn = HashMap::new();
        tcp_conn.insert("src-address".to_string(), "192.168.1.100:12345".to_string());
        tcp_conn.insert("protocol".to_string(), "tcp".to_string());

        let mut udp_conn = HashMap::new();
        udp_conn.insert("src-address".to_string(), "192.168.1.100:12346".to_string());
        udp_conn.insert("protocol".to_string(), "udp".to_string());

        let result = parse_connection_tracking(&[tcp_conn, udp_conn], "ipv4");

        assert_eq!(result.len(), 2);
        let tcp = result.iter().find(|r| r.protocol == "tcp").unwrap();
        let udp = result.iter().find(|r| r.protocol == "udp").unwrap();
        assert_eq!(tcp.connection_count, 1);
        assert_eq!(udp.connection_count, 1);
    }

    #[test]
    fn test_parse_connection_tracking_missing_src_address() {
        let mut conn = HashMap::new();
        conn.insert("protocol".to_string(), "tcp".to_string());

        let result = parse_connection_tracking(&[conn], "ipv4");

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_connection_tracking_no_protocol() {
        let mut conn = HashMap::new();
        conn.insert("src-address".to_string(), "192.168.1.100:12345".to_string());

        let result = parse_connection_tracking(&[conn], "ipv4");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src_address, "192.168.1.100");
        assert_eq!(result[0].protocol, "unknown");
        assert_eq!(result[0].connection_count, 1);
        assert_eq!(result[0].ip_version, "ipv4");
    }

    #[test]
    fn test_parse_connection_tracking_ipv6() {
        let mut conn = HashMap::new();
        conn.insert("src-address".to_string(), "[::1]:12345".to_string());
        conn.insert("protocol".to_string(), "tcp".to_string());

        let result = parse_connection_tracking(&[conn], "ipv6");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src_address, "::1");
        assert_eq!(result[0].protocol, "tcp");
        assert_eq!(result[0].ip_version, "ipv6");
    }
}
