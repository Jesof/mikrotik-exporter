// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Connection tracking collection group.

use crate::mikrotik::client::MikroTikClient;
use crate::mikrotik::responses::parse_connection_tracking;
use crate::prelude::Result;
use secrecy::ExposeSecret;

pub(crate) async fn collect_group_conntrack(
    client: &MikroTikClient,
) -> Result<super::super::ConntrackGroupData> {
    const CONNTRACK_COMMANDS: [(&str, &str); 2] = [
        ("/ip/firewall/connection/print", "ipv4"),
        ("/ipv6/firewall/connection/print", "ipv6"),
    ];

    let mut guard = client
        .pool
        .get_connection(
            &client.config.address,
            &client.config.username,
            client.config.password.expose_secret(),
            Some("conntrack"),
        )
        .await?;

    let conn = guard.get_mut();
    let mut conntrack_results = Vec::with_capacity(CONNTRACK_COMMANDS.len());
    for (path, ip_version) in CONNTRACK_COMMANDS {
        conntrack_results.push((ip_version, conn.command(path, &[]).await));
    }

    let success = conntrack_results
        .iter()
        .any(|(_ip_version, result)| result.is_ok());
    client
        .record_group_result(&mut guard, "conntrack", success)
        .await;

    drop(guard);

    if !success {
        return Err(crate::prelude::AppError::RouterOs(format!(
            "Router '{}' conntrack collection failed for both IPv4 and IPv6",
            client.config.name
        )));
    }

    let mut entries = Vec::new();
    let mut complete_ok = true;

    for (ip_version, result) in conntrack_results {
        complete_ok &= result.is_ok();
        entries.extend(parse_connection_tracking(
            &result.unwrap_or_default(),
            ip_version,
        ));
    }

    Ok(super::super::ConntrackGroupData {
        entries,
        complete_ok,
    })
}
