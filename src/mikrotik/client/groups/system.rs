// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! System and interface collection group.

use crate::mikrotik::client::MikroTikClient;
use crate::mikrotik::responses::{parse_interfaces, parse_system};
use crate::prelude::Result;
use secrecy::ExposeSecret;

pub(crate) async fn collect_group_system_interfaces(
    client: &MikroTikClient,
) -> Result<super::super::SystemInterfacesGroupData> {
    let mut guard = client
        .pool
        .get_connection(
            &client.config.address,
            &client.config.username,
            client.config.password.expose_secret(),
            Some("system"),
        )
        .await?;

    let conn = guard.get_mut();
    let system_result = conn
        .command(
            "/system/resource/print",
            &[".proplist=uptime,cpu-load,free-memory,total-memory,version,board-name"],
        )
        .await;
    let interfaces_result = conn
        .command(
            "/interface/print",
            &[".proplist=.id,name,comment,type,rx-byte,tx-byte,rx-packet,tx-packet,rx-error,tx-error,running"],
        )
        .await;

    let interfaces_count = interfaces_result.as_ref().map(Vec::len).unwrap_or(0);
    let empty_interfaces_anomaly = interfaces_count == 0 && interfaces_result.is_ok();
    let success = system_result.is_ok() && interfaces_result.is_ok() && !empty_interfaces_anomaly;

    if empty_interfaces_anomaly {
        tracing::warn!(
            "Router '{}' /interface/print returned empty response, forcing reconnect",
            client.config.name
        );
        guard.mark_broken();
    }

    client
        .record_group_result(&mut guard, "system", success)
        .await;

    drop(guard);

    if empty_interfaces_anomaly {
        return Err(crate::prelude::AppError::RouterOs(
            "inconsistent snapshot: /interface/print returned empty response".to_string(),
        ));
    }

    let system = parse_system(&system_result?);
    let interfaces = parse_interfaces(&interfaces_result?);

    Ok(super::super::SystemInterfacesGroupData { system, interfaces })
}
