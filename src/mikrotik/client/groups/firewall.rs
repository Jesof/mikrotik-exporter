// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Firewall collection group.

use crate::mikrotik::client::MikroTikClient;
use crate::mikrotik::responses::parse_firewall_rules;
use crate::prelude::Result;
use secrecy::ExposeSecret;

use super::common::parse_count_only;

pub(crate) async fn collect_group_firewall(
    client: &MikroTikClient,
) -> Result<super::super::FirewallGroupData> {
    const FIREWALL_PROPLIST: &str = ".proplist=.id,chain,action,bytes,packets,disabled";
    const FIREWALL_SECTIONS: [(&str, &str, &str); 8] = [
        ("/ip/firewall/filter/print", "ipv4", "filter"),
        ("/ip/firewall/nat/print", "ipv4", "nat"),
        ("/ip/firewall/mangle/print", "ipv4", "mangle"),
        ("/ip/firewall/raw/print", "ipv4", "raw"),
        ("/ipv6/firewall/filter/print", "ipv6", "filter"),
        ("/ipv6/firewall/nat/print", "ipv6", "nat"),
        ("/ipv6/firewall/mangle/print", "ipv6", "mangle"),
        ("/ipv6/firewall/raw/print", "ipv6", "raw"),
    ];

    let mut guard = client
        .pool
        .get_connection(
            &client.config.address,
            &client.config.username,
            client.config.password.expose_secret(),
            Some("firewall"),
        )
        .await?;

    let conn = guard.get_mut();

    let mut section_results = Vec::with_capacity(FIREWALL_SECTIONS.len());
    let mut inconsistent_sections = Vec::new();

    for (path, ip_version, section) in FIREWALL_SECTIONS {
        let section_result = conn.command(path, &[FIREWALL_PROPLIST]).await;

        if matches!(&section_result, Ok(rows) if rows.is_empty()) {
            let count = conn
                .command(path, &["=count-only="])
                .await
                .ok()
                .and_then(|rows| parse_count_only(&rows))
                .unwrap_or(0);

            if count > 0 {
                inconsistent_sections.push(format!("{ip_version}/{section}"));
            }
        }

        section_results.push((ip_version, section, section_result));
    }

    let has_inconsistent_snapshot = !inconsistent_sections.is_empty();
    let success = section_results
        .iter()
        .any(|(_ip_version, _section, result)| result.is_ok())
        && !has_inconsistent_snapshot;
    client
        .record_group_result(&mut guard, "firewall", success)
        .await;

    drop(guard);

    if has_inconsistent_snapshot {
        return Err(crate::prelude::AppError::RouterOs(format!(
            "inconsistent snapshot: firewall count mismatch in sections {}",
            inconsistent_sections.join(",")
        )));
    }

    if !success {
        return Err(crate::prelude::AppError::RouterOs(format!(
            "Router '{}' firewall collection failed",
            client.config.name
        )));
    }

    let mut firewall_rules = Vec::new();
    let mut complete_ok = true;

    for (ip_version, section, result) in section_results {
        complete_ok &= result.is_ok();
        firewall_rules.extend(parse_firewall_rules(
            &result.unwrap_or_default(),
            ip_version,
            section,
        ));
    }

    Ok(super::super::FirewallGroupData {
        rules: firewall_rules,
        complete_ok,
    })
}
