// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use super::common::{parse_u64_field, required_field};
use crate::mikrotik::types::InterfaceStats;
use crate::prelude::{AppError, Result};
use std::collections::{HashMap, HashSet};

pub(crate) fn parse_interfaces(
    sentences: &[HashMap<String, String>],
) -> Result<Vec<InterfaceStats>> {
    let mut ids = HashSet::new();
    sentences
        .iter()
        .map(|s| {
            let id = required_field(s, ".id")?;
            if !ids.insert(id) {
                return Err(AppError::InvalidSnapshot("duplicate interface id".into()));
            }
            Ok(InterfaceStats {
                id: id.into(),
                name: required_field(s, "name")?.into(),
                comment: s.get("comment").cloned().unwrap_or_default(),
                rx_bytes: parse_u64_field(s, "rx-byte", "interface")?,
                tx_bytes: parse_u64_field(s, "tx-byte", "interface")?,
                rx_packets: parse_u64_field(s, "rx-packet", "interface")?,
                tx_packets: parse_u64_field(s, "tx-packet", "interface")?,
                // RouterOS omits these counters for some interface types and versions.
                // `None` preserves the distinction from a genuine zero so the registry
                // does not add a full lifetime value as a delta when the field returns.
                rx_errors: s
                    .get("rx-error")
                    .map(|_| parse_u64_field(s, "rx-error", "interface"))
                    .transpose()?,
                tx_errors: s
                    .get("tx-error")
                    .map(|_| parse_u64_field(s, "tx-error", "interface"))
                    .transpose()?,
                running: match required_field(s, "running")? {
                    "true" => true,
                    "false" => false,
                    _ => {
                        return Err(AppError::InvalidSnapshot(
                            "invalid interface running state".into(),
                        ));
                    }
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_malformed_counter_snapshot_preserves_baseline_on_recovery() {
        use crate::metrics::{MetricsRegistry, RouterLabels};
        use crate::mikrotik::responses::parse_firewall_rules;
        use crate::mikrotik::{RouterMetrics, SystemResource};
        let registry = MetricsRegistry::new();
        let labels = RouterLabels {
            router: "router1".into(),
        };
        let mut interface = interface_row();
        let mut rule: HashMap<String, String> = [
            (".id", "*1"),
            ("chain", "forward"),
            ("action", "accept"),
            ("bytes", "1000"),
            ("packets", "10"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let mut snapshot = RouterMetrics {
            router_name: labels.router.clone(),
            interfaces: parse_interfaces(&[interface.clone()]).unwrap(),
            firewall_rules: parse_firewall_rules(&[rule.clone()], "ipv4", "filter").unwrap(),
            system: SystemResource {
                uptime: "1d".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        registry.update_metrics(&snapshot);
        interface.insert("rx-byte".into(), "malformed".into());
        rule.remove("bytes");
        assert!(matches!(
            parse_interfaces(&[interface.clone()]),
            Err(AppError::InvalidSnapshot(_))
        ));
        assert!(matches!(
            parse_firewall_rules(&[rule.clone()], "ipv4", "filter"),
            Err(AppError::InvalidSnapshot(_))
        ));
        registry.record_scrape_error(&labels);
        assert!(
            registry
                .encode_metrics()
                .await
                .unwrap()
                .contains("mikrotik_interface_rx_bytes_total{router=\"router1\",id=\"*1\"} 1000")
        );
        interface.insert("rx-byte".into(), "1200".into());
        rule.insert("bytes".into(), "1300".into());
        snapshot.interfaces = parse_interfaces(&[interface]).unwrap();
        snapshot.firewall_rules = parse_firewall_rules(&[rule], "ipv4", "filter").unwrap();
        registry.update_metrics(&snapshot);
        let encoded = registry.encode_metrics().await.unwrap();
        assert!(
            encoded
                .contains("mikrotik_interface_rx_bytes_total{router=\"router1\",id=\"*1\"} 1200")
        );
        assert!(encoded.contains("mikrotik_firewall_rule_bytes_total{router=\"router1\",id=\"*1\",chain=\"forward\",action=\"accept\",ip_version=\"ipv4\",section=\"filter\"} 1300"));
    }

    pub(crate) fn interface_row() -> HashMap<String, String> {
        [
            (".id", "*1"),
            ("name", "ether1"),
            ("running", "true"),
            ("rx-byte", "1000"),
            ("tx-byte", "2000"),
            ("rx-packet", "10"),
            ("tx-packet", "20"),
            ("rx-error", "0"),
            ("tx-error", "0"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
    }

    #[test]
    fn test_interfaces_reject_entire_malformed_snapshot() {
        let valid = interface_row();
        assert_eq!(
            parse_interfaces(std::slice::from_ref(&valid)).unwrap()[0].rx_bytes,
            1000
        );
        for field in [
            ".id",
            "name",
            "running",
            "rx-byte",
            "tx-byte",
            "rx-packet",
            "tx-packet",
        ] {
            let mut invalid = valid.clone();
            invalid.remove(field);
            assert!(
                parse_interfaces(&[valid.clone(), invalid]).is_err(),
                "{field}"
            );
        }
        let mut invalid = valid.clone();
        invalid.insert("rx-byte".into(), "invalid".into());
        assert!(parse_interfaces(&[invalid]).is_err());
        assert!(parse_interfaces(&[valid.clone(), valid]).is_err());
        assert!(parse_interfaces(&[]).unwrap().is_empty());
    }

    #[test]
    fn test_interfaces_accept_missing_error_counters() {
        let mut row = interface_row();
        row.remove("rx-error");
        row.remove("tx-error");

        let interface = parse_interfaces(&[row]).unwrap().pop().unwrap();

        assert_eq!(interface.rx_errors, None);
        assert_eq!(interface.tx_errors, None);
    }
}
