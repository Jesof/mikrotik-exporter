// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Low-level RouterOS API connection handling

use md5::compute as md5_compute;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::types::{ConnectionTrackingStats, InterfaceStats, SystemResource};

/// Connection timeout (5 seconds)
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Read operation timeout (30 seconds)
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Low-level RouterOS API connection
pub(super) struct RouterOsConnection {
    stream: TcpStream,
}

impl RouterOsConnection {
    pub(super) async fn connect(
        addr: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        tracing::trace!("Attempting TCP connection to: {}", addr);
        let stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await??;
        tracing::trace!("TCP connection established to: {}", addr);
        Ok(Self { stream })
    }

    pub(super) async fn login(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::trace!("Attempting login for user: {}", username);
        // Try new login method first (RouterOS 6.43+)
        let login_result = self
            .raw_command(vec![
                "/login".to_string(),
                format!("=name={}", username),
                format!("=password={}", password),
            ])
            .await;

        match login_result {
            Ok(sentences) => {
                tracing::trace!(
                    "New login method response received, {} sentences",
                    sentences.len()
                );
                // Check for error messages
                for s in &sentences {
                    if let Some(msg) = s.get("message") {
                        if msg.contains("failure") || msg.contains("invalid") {
                            tracing::trace!("Login failed with message: {}", msg);
                            return Err(format!("Login failed: {msg}").into());
                        }
                        tracing::debug!("Login message: {}", msg);
                    }
                }
                tracing::debug!("Login successful (new method)");
                return Ok(());
            }
            Err(e) => {
                tracing::debug!("New login method failed, trying legacy method: {}", e);
            }
        }

        // Fallback to legacy challenge-response method (pre-6.43)
        tracing::trace!("Requesting challenge for legacy login");
        let sentences = self.raw_command(vec!["/login".to_string()]).await?;
        let mut challenge_hex = None;
        for s in sentences {
            if let Some(ret) = s.get("ret") {
                challenge_hex = Some(ret.clone());
            }
        }
        let challenge_hex = challenge_hex.ok_or("No challenge 'ret' received")?;
        tracing::trace!("Challenge received, length: {}", challenge_hex.len());
        let challenge = hex::decode(&challenge_hex)?;

        // Build MD5 hash of 0 + password + challenge
        let mut data = Vec::with_capacity(1 + password.len() + challenge.len());
        data.push(0u8);
        data.extend_from_slice(password.as_bytes());
        data.extend_from_slice(&challenge);
        let digest = md5_compute(&data);
        let mut response = String::from("00");
        response.push_str(&hex::encode(digest.0));

        let login_sentences = self
            .raw_command(vec![
                "/login".to_string(),
                format!("=name={}", username),
                format!("=response={}", response),
            ])
            .await?;
        // If no !trap assume success
        for s in &login_sentences {
            if s.contains_key("message") {
                tracing::warn!("Login message: {:?}", s.get("message"));
            }
        }
        tracing::debug!("Login successful (legacy method)");
        Ok(())
    }

    pub(super) async fn command(
        &mut self,
        path: &str,
        args: &[&str],
    ) -> Result<Vec<HashMap<String, String>>, Box<dyn std::error::Error + Send + Sync>> {
        let mut words: Vec<String> = Vec::with_capacity(1 + args.len());
        words.push(path.to_string());
        for a in args {
            words.push((*a).to_string());
        }
        self.raw_command(words).await
    }

    async fn raw_command(
        &mut self,
        words: Vec<String>,
    ) -> Result<Vec<HashMap<String, String>>, Box<dyn std::error::Error + Send + Sync>> {
        self.send_words(&words).await?;
        self.read_sentences().await
    }

    async fn send_words(
        &mut self,
        words: &[String],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for w in words {
            self.write_word(w).await?;
        }
        // zero length word terminator
        self.stream.write_all(&[0]).await?;
        Ok(())
    }

    async fn write_word(
        &mut self,
        word: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bytes = word.as_bytes();
        self.stream.write_all(&encode_length(bytes.len())).await?;
        self.stream.write_all(bytes).await?;
        Ok(())
    }

    async fn read_sentences(
        &mut self,
    ) -> Result<Vec<HashMap<String, String>>, Box<dyn std::error::Error + Send + Sync>> {
        // Wrap the entire read operation in a timeout to prevent hanging on slow/dead connections
        timeout(READ_TIMEOUT, async {
            let mut sentences: Vec<HashMap<String, String>> = Vec::new();
            let mut current: Option<HashMap<String, String>> = None;
            loop {
                let word = self.read_word().await?;
                if word.is_empty() {
                    continue;
                }
                tracing::trace!("Received word: {}", word);
                if word == "!done" {
                    if let Some(s) = current.take() {
                        sentences.push(s);
                    }
                    tracing::trace!("Command complete, {} sentences received", sentences.len());
                    break;
                }
                if word == "!trap" {
                    tracing::trace!("Trap received, reading trap details");
                    // collect trap details
                    let mut trap = HashMap::new();
                    loop {
                        let w = self.read_word().await?;
                        if w.is_empty() {
                            continue;
                        }
                        if let Some(stripped) = w.strip_prefix('=') {
                            if let Some((k, v)) = stripped.split_once('=') {
                                trap.insert(k.to_string(), v.to_string());
                            }
                            continue;
                        }
                        if w.starts_with('!') || w == "!done" {
                            break;
                        }
                    }
                    let msg = trap
                        .get("message")
                        .cloned()
                        .unwrap_or_else(|| "trap".to_string());
                    return Err(format!("RouterOS trap: {msg}").into());
                }
                if word == "!re" {
                    if let Some(s) = current.take() {
                        sentences.push(s);
                    }
                    current = Some(HashMap::new());
                    continue;
                }
                if let Some(stripped) = word.strip_prefix('=') {
                    let tgt = current.get_or_insert(HashMap::new());
                    if let Some((k, v)) = stripped.split_once('=') {
                        tgt.insert(k.to_string(), v.to_string());
                    }
                }
                // ignore other headers
            }
            Ok(sentences)
        })
        .await
        .map_err(|_| "Read timeout: RouterOS did not respond within 30 seconds")?
    }

    async fn read_word(&mut self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let len = self.read_length().await?;
        if len == 0 {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(String::from_utf8_lossy(&buf).into())
    }

    async fn read_length(&mut self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let first = self.stream.read_u8().await?;
        let len = if first & 0x80 == 0 {
            first as usize
        } else if first & 0xC0 == 0x80 {
            let second = self.stream.read_u8().await?;
            (((first & 0x3F) as usize) << 8) + second as usize
        } else if first & 0xE0 == 0xC0 {
            let second = self.stream.read_u8().await?;
            let third = self.stream.read_u8().await?;
            (((first & 0x1F) as usize) << 16) + ((second as usize) << 8) + third as usize
        } else if first & 0xF0 == 0xE0 {
            let second = self.stream.read_u8().await?;
            let third = self.stream.read_u8().await?;
            let fourth = self.stream.read_u8().await?;
            (((first & 0x0F) as usize) << 24)
                + ((second as usize) << 16)
                + ((third as usize) << 8)
                + fourth as usize
        } else {
            // five byte length
            let b2 = self.stream.read_u8().await?;
            let b3 = self.stream.read_u8().await?;
            let b4 = self.stream.read_u8().await?;
            let b5 = self.stream.read_u8().await?;
            ((first & 0x07) as usize) << 32
                | (b2 as usize) << 24
                | (b3 as usize) << 16
                | (b4 as usize) << 8
                | b5 as usize
        };
        Ok(len)
    }
}

// RouterOS protocol length encoding - intentional truncation is part of the wire format
#[allow(clippy::cast_possible_truncation)]
fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x4000 {
        vec![((len >> 8) as u8) | 0x80, (len & 0xFF) as u8]
    } else if len < 0x0020_0000 {
        vec![
            ((len >> 16) as u8) | 0xC0,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    } else if len < 0x1000_0000 {
        vec![
            ((len >> 24) as u8) | 0xE0,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    } else {
        vec![
            ((len >> 32) as u8) | 0xF0,
            ((len >> 24) & 0xFF) as u8,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

pub(super) fn parse_system(sentences: &[HashMap<String, String>]) -> SystemResource {
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

pub(super) fn parse_interfaces(sentences: &[HashMap<String, String>]) -> Vec<InterfaceStats> {
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
pub(super) fn parse_connection_tracking(
    sentences: &[HashMap<String, String>],
    ip_version: &str,
) -> Vec<ConnectionTrackingStats> {
    use std::collections::HashMap;

    // Aggregate connections by (src_address, protocol)
    let mut aggregated: HashMap<(String, String), u64> = HashMap::new();

    for s in sentences {
        if let Some(src) = s.get("src-address") {
            // Extract IP without port (format: "192.168.1.1:12345")
            let src_ip = src.split(':').next().unwrap_or(src);
            let protocol = s
                .get("protocol")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let key = (src_ip.to_string(), protocol);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_length_small() {
        assert_eq!(encode_length(0), vec![0]);
        assert_eq!(encode_length(1), vec![1]);
        assert_eq!(encode_length(127), vec![127]);
    }

    #[test]
    fn test_encode_length_medium() {
        assert_eq!(encode_length(128), vec![0x80, 0x80]);
        assert_eq!(encode_length(256), vec![0x81, 0x00]);
        assert_eq!(encode_length(0x3FFF), vec![0xBF, 0xFF]);
    }

    #[test]
    fn test_encode_length_large() {
        assert_eq!(encode_length(0x4000), vec![0xC0, 0x40, 0x00]);
        assert_eq!(encode_length(0x1F_FFFF), vec![0xDF, 0xFF, 0xFF]);
    }

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
        assert_eq!(result[0].src_address, "[");
        assert_eq!(result[0].protocol, "tcp");
        assert_eq!(result[0].ip_version, "ipv6");
    }
}
