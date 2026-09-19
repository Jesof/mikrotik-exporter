// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use super::common::{parse_u64_field, required_field};
use crate::metrics::parsers::parse_uptime_to_seconds;
use crate::mikrotik::SnapshotError;
use crate::mikrotik::types::WireGuardPeerStats;
use crate::prelude::{AppError, Result};
use std::collections::HashMap;
use std::time::SystemTime;

pub(crate) fn parse_wireguard_peers(
    sentences: &[HashMap<String, String>],
) -> Result<Vec<WireGuardPeerStats>> {
    sentences
        .iter()
        .filter(|s| {
            !s.get("disabled")
                .is_some_and(|v| v.eq_ignore_ascii_case("true"))
        })
        .map(|s| {
            let rx_bytes = parse_u64_field(s, "rx", "wireguard")?;
            let tx_bytes = parse_u64_field(s, "tx", "wireguard")?;
            if rx_bytes > i64::MAX as u64 || tx_bytes > i64::MAX as u64 {
                return Err(AppError::InvalidSnapshot(
                    SnapshotError::WireguardByteCountOutOfRange,
                ));
            }
            let latest_handshake = s
                .get("last-handshake")
                .or_else(|| s.get("latest-handshake"))
                .map(|v| parse_handshake_to_timestamp(v))
                .transpose()?
                .flatten();
            Ok(WireGuardPeerStats {
                id: required_field(s, ".id")?.into(),
                interface: required_field(s, "interface")?.into(),
                name: s
                    .get("name")
                    .cloned()
                    .unwrap_or_else(|| "unnamed-peer".into()),
                comment: s.get("comment").cloned().unwrap_or_default(),
                allowed_address: required_field(s, "allowed-address")?.into(),
                endpoint: s
                    .get("current-endpoint-address")
                    .or_else(|| s.get("endpoint"))
                    .filter(|v| !v.is_empty())
                    .cloned(),
                rx_bytes,
                tx_bytes,
                latest_handshake,
            })
        })
        .collect()
}

fn parse_handshake_to_timestamp(value: &str) -> Result<Option<u64>> {
    if value.is_empty() || value == "never" {
        return Ok(None);
    }
    let invalid = || AppError::InvalidSnapshot(SnapshotError::InvalidWireguardHandshake);
    let elapsed = parse_uptime_to_seconds(value).ok_or_else(invalid)?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_secs();
    Ok(Some(now.checked_sub(elapsed).ok_or_else(invalid)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wireguard_validation() {
        let row: HashMap<String, String> = [
            (".id", "*1"),
            ("interface", "wg1"),
            ("allowed-address", "10.0.0.1/32"),
            ("rx", "1024"),
            ("tx", "2048"),
            ("last-handshake", "never"),
            ("current-endpoint-address", "2001:db8::1"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let parsed = parse_wireguard_peers(std::slice::from_ref(&row)).unwrap();
        assert_eq!(parsed[0].rx_bytes, 1024);
        assert_eq!(parsed[0].name, "unnamed-peer");
        assert_eq!(parsed[0].endpoint.as_deref(), Some("2001:db8::1"));
        assert_eq!(parsed[0].latest_handshake, None);
        for field in [".id", "interface", "allowed-address", "rx", "tx"] {
            let mut invalid = row.clone();
            invalid.remove(field);
            assert!(parse_wireguard_peers(&[invalid]).is_err());
        }
        let mut invalid = row.clone();
        invalid.insert("rx".into(), "invalid".into());
        assert!(parse_wireguard_peers(&[invalid]).is_err());
        for field in ["rx", "tx"] {
            let mut invalid = row.clone();
            invalid.insert(field.into(), u64::MAX.to_string());
            assert!(matches!(
                parse_wireguard_peers(&[invalid]),
                Err(AppError::InvalidSnapshot(_))
            ));
        }
        let mut disabled = row;
        disabled.insert("disabled".into(), "true".into());
        disabled.remove("rx");
        assert!(parse_wireguard_peers(&[disabled]).unwrap().is_empty());
        assert!(parse_wireguard_peers(&[]).unwrap().is_empty());
    }

    #[test]
    fn test_handshake_invalid_duration_never_becomes_current_time() {
        for input in [
            "invalid",
            "1hgarbage",
            "1m2",
            "18446744073709551615w",
            "18446744073709551615",
        ] {
            assert!(parse_handshake_to_timestamp(input).is_err(), "{input}");
        }
        for input in ["", "never"] {
            assert_eq!(parse_handshake_to_timestamp(input).unwrap(), None);
        }
        for input in ["120", "1m30s", "00:01:30"] {
            let before = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let timestamp = parse_handshake_to_timestamp(input).unwrap().unwrap();
            assert!(timestamp <= before - 89);
            assert!(timestamp >= before - 120);
        }
    }
}
