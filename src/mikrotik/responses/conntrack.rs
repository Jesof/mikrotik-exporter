// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Connection tracking parsing

use crate::mikrotik::SnapshotError;
use crate::mikrotik::types::ConnectionTrackingStats;
use crate::prelude::{AppError, Result};
use std::collections::HashMap;

pub(crate) fn parse_connection_tracking(
    sentences: &[HashMap<String, String>],
    ip_version: &str,
) -> Result<Vec<ConnectionTrackingStats>> {
    let mut aggregated: HashMap<(String, String), u64> = HashMap::new();

    for s in sentences {
        {
            let src = super::common::required_field(s, "src-address")?;
            let src_ip = extract_src_ip(src)?;
            let protocol = super::common::required_field(s, "protocol")?.to_string();
            let key = (src_ip, protocol);
            *aggregated.entry(key).or_insert(0) += 1;
        }
    }

    Ok(aggregated
        .into_iter()
        .map(|((src_address, protocol), count)| ConnectionTrackingStats {
            src_address,
            protocol,
            connection_count: count,
            ip_version: ip_version.to_string(),
        })
        .collect())
}

fn extract_src_ip(src: &str) -> Result<String> {
    if let Ok(ip) = src.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    if let Ok(socket) = src.parse::<std::net::SocketAddr>() {
        return Ok(socket.ip().to_string());
    }

    // Bracketed IPv6, optionally followed by a port (for example the scoped
    // `[fe80::1%br1]:1234` form, which `SocketAddr` rejects).
    if let Some(rest) = src.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
        && (tail.is_empty()
            || tail
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok()))
    {
        return parse_scoped_ipv6(host);
    }

    parse_scoped_ipv6(src)
}

/// Parses an IPv6 host, ignoring a trailing `RouterOS` interface zone.
///
/// Link-local connection rows carry a zone scope (for example `fe80::1%br1`),
/// which `std::net` rejects. The zone identifies the local interface and is not
/// part of the address, so the canonicalized series addresses remain stable.
fn parse_scoped_ipv6(host: &str) -> Result<String> {
    let host = host.split_once('%').map_or(host, |(address, _)| address);
    host.parse::<std::net::Ipv6Addr>()
        .map(|ip| ip.to_string())
        .map_err(|_| AppError::InvalidSnapshot(SnapshotError::InvalidConntrackSourceAddress))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bare_ipv6_address_keeps_final_segment() {
        for src in [
            "2001:db8::1",
            "2001:db8::1234",
            "::1",
            "2001:db8:0:1:2:3:4:5",
        ] {
            assert_eq!(
                extract_src_ip(src).unwrap(),
                src.parse::<std::net::IpAddr>().unwrap().to_string()
            );
        }
        assert_eq!(extract_src_ip("[2001:db8::1]:1234").unwrap(), "2001:db8::1");
        assert_eq!(extract_src_ip("192.0.2.1:1234").unwrap(), "192.0.2.1");
        for invalid in [
            "invalid",
            "192.0.2.1:no-port",
            "[::1]garbage",
            "[::1]:65536",
        ] {
            assert!(extract_src_ip(invalid).is_err());
        }
    }

    #[test]
    fn test_scoped_ipv6_zone_stripped_before_parsing() {
        assert_eq!(extract_src_ip("fe80::1%br1").unwrap(), "fe80::1");
        assert_eq!(extract_src_ip("[fe80::1%br1]").unwrap(), "fe80::1");
        assert_eq!(extract_src_ip("[fe80::1%br1]:1234").unwrap(), "fe80::1");
    }

    #[test]
    fn test_parse_connection_tracking_scoped_ipv6_accepted() {
        let mut conn = HashMap::new();
        conn.insert("src-address".to_string(), "fe80::1%br1:12345".to_string());
        conn.insert("protocol".to_string(), "tcp".to_string());

        let result = parse_connection_tracking(&[conn], "ipv6").unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src_address, "fe80::1");
        assert_eq!(result[0].protocol, "tcp");
        assert_eq!(result[0].ip_version, "ipv6");
    }

    #[test]
    fn test_parse_connection_tracking_empty() {
        let result = parse_connection_tracking(&[], "ipv4").unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_connection_tracking_single() {
        let mut conn = HashMap::new();
        conn.insert("src-address".to_string(), "192.168.1.100:12345".to_string());
        conn.insert("dst-address".to_string(), "8.8.8.8:53".to_string());
        conn.insert("protocol".to_string(), "udp".to_string());

        let result = parse_connection_tracking(&[conn], "ipv4").unwrap();

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

        let result = parse_connection_tracking(&[conn1, conn2], "ipv4").unwrap();

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

        let result = parse_connection_tracking(&[tcp_conn, udp_conn], "ipv4").unwrap();

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

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_connection_tracking_no_protocol() {
        let mut conn = HashMap::new();
        conn.insert("src-address".to_string(), "192.168.1.100:12345".to_string());

        let result = parse_connection_tracking(&[conn], "ipv4");

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_connection_tracking_ipv6() {
        let mut conn = HashMap::new();
        conn.insert("src-address".to_string(), "[::1]:12345".to_string());
        conn.insert("protocol".to_string(), "tcp".to_string());

        let result = parse_connection_tracking(&[conn], "ipv6").unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src_address, "::1");
        assert_eq!(result[0].protocol, "tcp");
        assert_eq!(result[0].ip_version, "ipv6");
    }
}
