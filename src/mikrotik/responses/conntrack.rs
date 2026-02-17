// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Connection tracking parsing

use crate::mikrotik::types::ConnectionTrackingStats;
use std::collections::HashMap;

pub(crate) fn parse_connection_tracking(
    sentences: &[HashMap<String, String>],
    ip_version: &str,
) -> Vec<ConnectionTrackingStats> {
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
