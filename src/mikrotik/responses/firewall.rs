// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use super::common::{parse_u64_field, required_field};
use crate::mikrotik::SnapshotError;
use crate::mikrotik::types::FirewallRuleStats;
use crate::prelude::{AppError, Result};
use std::collections::{HashMap, HashSet};

pub(crate) fn parse_firewall_rules(
    sentences: &[HashMap<String, String>],
    ip_version: &str,
    section: &str,
) -> Result<Vec<FirewallRuleStats>> {
    let mut ids = HashSet::new();
    sentences
        .iter()
        .filter(|s| s.get("disabled").is_none_or(|v| v != "true"))
        .map(|s| {
            let id = required_field(s, ".id")?;
            if !ids.insert(id) {
                return Err(AppError::InvalidSnapshot(SnapshotError::DuplicateId {
                    kind: "firewall",
                }));
            }
            Ok(FirewallRuleStats {
                id: id.into(),
                comment: s.get("comment").cloned().unwrap_or_default(),
                chain: required_field(s, "chain")?.into(),
                action: required_field(s, "action")?.into(),
                bytes: parse_u64_field(s, "bytes", "firewall")?,
                packets: parse_u64_field(s, "packets", "firewall")?,
                ip_version: ip_version.into(),
                section: section.into(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_firewall_validation() {
        let row: HashMap<String, String> = [
            (".id", "*1"),
            ("chain", "input"),
            ("action", "accept"),
            ("bytes", "1024"),
            ("packets", "5"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let parsed = parse_firewall_rules(std::slice::from_ref(&row), "ipv6", "filter").unwrap();
        assert_eq!(parsed[0].bytes, 1024);
        assert_eq!(parsed[0].ip_version, "ipv6");
        assert_eq!(parsed[0].section, "filter");
        for field in [".id", "chain", "action", "bytes", "packets"] {
            let mut invalid = row.clone();
            invalid.remove(field);
            assert!(parse_firewall_rules(&[invalid], "ipv4", "filter").is_err());
        }
        for value in ["invalid", "-1", "18446744073709551616"] {
            let mut invalid = row.clone();
            invalid.insert("bytes".into(), value.into());
            assert!(parse_firewall_rules(&[invalid], "ipv4", "filter").is_err());
        }
        let mut disabled = row;
        disabled.insert("disabled".into(), "true".into());
        disabled.remove("bytes");
        assert!(
            parse_firewall_rules(&[disabled], "ipv4", "filter")
                .unwrap()
                .is_empty()
        );
        assert!(
            parse_firewall_rules(&[], "ipv4", "filter")
                .unwrap()
                .is_empty()
        );
    }
}
