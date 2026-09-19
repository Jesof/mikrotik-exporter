// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! System and interface collection group.

use secrecy::ExposeSecret;

use crate::mikrotik::SnapshotError;
use crate::mikrotik::client::MikroTikClient;
use crate::mikrotik::responses::{parse_interfaces, parse_system};
use crate::prelude::Result;

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
            client.config.tls.as_ref(),
        )
        .await?;

    let conn = guard.get_mut();
    let system_result = conn
        .command(
            "/system/resource/print",
            &["=.proplist=uptime,cpu-load,free-memory,total-memory,version,board-name"],
        )
        .await;
    let interfaces_result = conn
        .command(
            "/interface/print",
            &["=.proplist=.id,name,comment,type,rx-byte,tx-byte,rx-packet,tx-packet,rx-error,tx-error,running"],
        )
        .await;

    let interfaces_count = interfaces_result.as_ref().map_or(0, Vec::len);
    let empty_interfaces_anomaly = interfaces_count == 0 && interfaces_result.is_ok();
    let connection_failed = [&system_result, &interfaces_result]
        .into_iter()
        .any(|result| {
            result
                .as_ref()
                .err()
                .is_some_and(crate::prelude::AppError::is_connection_level)
        });
    let parsed = system_result
        .and_then(|rows| parse_system(&rows))
        .and_then(|system| {
            let interfaces = parse_interfaces(&interfaces_result?)?;
            if empty_interfaces_anomaly {
                return Err(crate::prelude::AppError::InvalidSnapshot(
                    SnapshotError::EmptyInterfaceSnapshot,
                ));
            }
            Ok(super::super::SystemInterfacesGroupData { system, interfaces })
        });

    if empty_interfaces_anomaly {
        tracing::warn!(
            router = %client.config.name,
            "Empty /interface/print response, forcing reconnect"
        );
        guard.mark_broken();
    }

    client
        .record_group_result(&mut guard, connection_failed)
        .await;

    drop(guard);

    parsed
}
