// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Firewall collection group.

use secrecy::ExposeSecret;

use crate::mikrotik::SnapshotError;
use crate::mikrotik::client::MikroTikClient;
use crate::mikrotik::responses::parse_firewall_rules;
use crate::prelude::Result;

pub(crate) async fn collect_group_firewall(
    client: &MikroTikClient,
) -> Result<super::super::FirewallGroupData> {
    const FIREWALL_PROPLIST: &str = "=.proplist=.id,chain,action,bytes,packets,disabled,comment";
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
            client.config.tls.as_ref(),
        )
        .await?;

    let conn = guard.get_mut();

    let mut section_results = Vec::with_capacity(FIREWALL_SECTIONS.len());
    let mut inconsistent_sections = Vec::new();

    for (path, ip_version, section) in FIREWALL_SECTIONS {
        let mut section_result = conn.command(path, &[FIREWALL_PROPLIST]).await;

        if matches!(&section_result, Ok(rows) if rows.is_empty()) {
            match conn.count_only(path).await {
                Ok(0) => {}
                Ok(_) => {
                    inconsistent_sections.push(format!("{ip_version}/{section}"));
                    section_result = Err(crate::prelude::AppError::InvalidSnapshot(
                        SnapshotError::UnverifiedEmptyFirewallSnapshot,
                    ));
                }
                // Preserve the typed cause (for example a timeout that leaves the
                // connection dirty) instead of silently degrading to a mismatch.
                Err(error) => section_result = Err(error),
            }
        }

        section_results
            .push(section_result.and_then(|rows| parse_firewall_rules(&rows, ip_version, section)));
    }

    let has_inconsistent_snapshot = !inconsistent_sections.is_empty();
    let connection_failed = section_results.iter().any(|result| {
        result
            .as_ref()
            .err()
            .is_some_and(crate::prelude::AppError::is_connection_level)
    });
    client
        .record_group_result(&mut guard, connection_failed)
        .await;

    drop(guard);

    if has_inconsistent_snapshot {
        return Err(crate::prelude::AppError::InvalidSnapshot(
            SnapshotError::FirewallCountMismatch {
                sections: inconsistent_sections.join(","),
            },
        ));
    }

    if let Some(index) = section_results
        .iter()
        .position(|result| matches!(result, Err(crate::prelude::AppError::InvalidSnapshot(_))))
    {
        return section_results
            .remove(index)
            .map(|_| super::super::FirewallGroupData::default());
    }

    if section_results.iter().all(Result::is_err) {
        return Err(crate::prelude::AppError::RouterOs(format!(
            "Router '{}' firewall collection failed",
            client.config.name
        )));
    }

    let mut firewall_rules = Vec::new();
    let mut complete_ok = true;

    for result in section_results {
        complete_ok &= result.is_ok();
        firewall_rules.extend(result.unwrap_or_default());
    }

    Ok(super::super::FirewallGroupData {
        rules: firewall_rules,
        complete_ok,
    })
}
