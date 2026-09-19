// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Connection tracking collection group.

use secrecy::ExposeSecret;

use crate::mikrotik::client::MikroTikClient;
use crate::mikrotik::responses::parse_connection_tracking;
use crate::prelude::Result;

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
            client.config.tls.as_ref(),
        )
        .await?;

    let conn = guard.get_mut();
    let mut conntrack_results = Vec::with_capacity(CONNTRACK_COMMANDS.len());
    for (path, ip_version) in CONNTRACK_COMMANDS {
        conntrack_results.push((
            ip_version,
            conn.command(path, &[])
                .await
                .and_then(|rows| parse_connection_tracking(&rows, ip_version)),
        ));
    }

    let any_success = conntrack_results.iter().any(|(_, result)| result.is_ok());
    let connection_failed = conntrack_results.iter().any(|(_, result)| {
        result
            .as_ref()
            .err()
            .is_some_and(crate::prelude::AppError::is_connection_level)
    });
    client
        .record_group_result(&mut guard, connection_failed)
        .await;

    drop(guard);

    // If every family failed with an unparsable snapshot, propagate the typed
    // error so the whole-router invalid-snapshot guard still sees it.
    if let Some(index) = conntrack_results
        .iter()
        .position(|(_, result)| matches!(result, Err(crate::prelude::AppError::InvalidSnapshot(_))))
        && !any_success
    {
        return conntrack_results
            .remove(index)
            .1
            .map(|_| super::super::ConntrackGroupData::default());
    }

    // Salvage per family: one malformed row in a single family is a query-level
    // failure that must not discard the healthy other family's data. The group
    // reports partial (complete_ok=false) so the unparsable data stays visible
    // via the completeness gauge instead of silently blanking both families.
    if !any_success {
        return Err(crate::prelude::AppError::CollectionFailed {
            groups: &["conntrack"],
        });
    }

    let mut entries = Vec::new();
    let mut complete_ok = true;

    for (_, result) in conntrack_results {
        match result {
            Ok(rows) => entries.extend(rows),
            Err(_) => complete_ok = false,
        }
    }
    if entries.is_empty() && !complete_ok {
        return Err(crate::prelude::AppError::CollectionFailed {
            groups: &["conntrack"],
        });
    }

    Ok(super::super::ConntrackGroupData {
        entries,
        complete_ok,
    })
}
