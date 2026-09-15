// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! `WireGuard` and certificate collection group.

use crate::mikrotik::client::MikroTikClient;
use crate::mikrotik::responses::{parse_certificates, parse_wireguard_peers};
use crate::prelude::Result;
use secrecy::ExposeSecret;

pub(crate) async fn collect_group_vpn_certs(
    client: &MikroTikClient,
) -> Result<super::super::VpnCertGroupData> {
    let mut guard = client
        .pool
        .get_connection(
            &client.config.address,
            &client.config.username,
            client.config.password.expose_secret(),
            Some("vpn"),
            client.config.tls.as_ref(),
        )
        .await?;

    let conn = guard.get_mut();
    let wireguard_peers_result = conn.command("/interface/wireguard/peers/print", &[]).await;
    let certificates_result = conn
        .command(
            "/certificate/print",
            &["=.proplist=.id,name,invalid-after,expiration"],
        )
        .await;

    let wireguard_count = if matches!(&wireguard_peers_result, Ok(rows) if rows.is_empty()) {
        conn.count_only("/interface/wireguard/peers/print")
            .await
            .ok()
    } else {
        None
    };

    let wireguard_inconsistent = matches!(&wireguard_peers_result, Ok(rows) if rows.is_empty())
        && wireguard_count != Some(0);
    let wireguard_peers_result =
        wireguard_peers_result.and_then(|rows| parse_wireguard_peers(&rows));
    let certificates_result = certificates_result.and_then(|rows| parse_certificates(&rows));
    let wireguard_ok = wireguard_peers_result.is_ok();
    let certificates_ok = certificates_result.is_ok();

    let success = wireguard_ok && certificates_ok && !wireguard_inconsistent;
    client.record_group_result(&mut guard, "vpn", success).await;

    drop(guard);

    if wireguard_inconsistent {
        return Err(crate::prelude::AppError::InvalidSnapshot(
            "inconsistent snapshot: wireguard peers count mismatch".to_string(),
        ));
    }

    if matches!(
        &wireguard_peers_result,
        Err(crate::prelude::AppError::InvalidSnapshot(_))
    ) {
        return wireguard_peers_result.map(|_| super::super::VpnCertGroupData::default());
    }
    if matches!(
        &certificates_result,
        Err(crate::prelude::AppError::InvalidSnapshot(_))
    ) {
        return certificates_result.map(|_| super::super::VpnCertGroupData::default());
    }
    if !wireguard_ok && !certificates_ok {
        return Err(crate::prelude::AppError::RouterOs(format!(
            "Router '{}' VPN/certificate collection failed",
            client.config.name
        )));
    }

    Ok(super::super::VpnCertGroupData {
        wireguard_peers: wireguard_peers_result.unwrap_or_default(),
        certificate_stats: certificates_result.unwrap_or_default(),
        wireguard_ok,
        certificates_ok,
    })
}
