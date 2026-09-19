// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! `WireGuard` and certificate collection group.

use secrecy::ExposeSecret;

use crate::mikrotik::SnapshotError;
use crate::mikrotik::client::MikroTikClient;
use crate::mikrotik::responses::{parse_certificates, parse_wireguard_peers};
use crate::mikrotik::types::CertificateStats;
use crate::prelude::Result;

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

    let mut wireguard_inconsistent = false;
    let mut wireguard_count_error = None;
    if matches!(&wireguard_peers_result, Ok(rows) if rows.is_empty()) {
        match conn.count_only("/interface/wireguard/peers/print").await {
            Ok(0) => {}
            Ok(_) => wireguard_inconsistent = true,
            // Preserve the typed cause instead of silently degrading to a mismatch.
            Err(error) => wireguard_count_error = Some(error),
        }
    }
    let wireguard_peers_result = match wireguard_count_error {
        Some(error) => Err(error),
        None => wireguard_peers_result.and_then(|rows| parse_wireguard_peers(&rows)),
    };
    let raw_certificate_rows = certificates_result.as_ref().map_or(0, Vec::len);
    let certificates_result = certificates_result.and_then(|rows| parse_certificates(&rows));
    let wireguard_ok = wireguard_peers_result.is_ok();
    let certificates_ok = certificates_result.is_ok();
    // Rows without a usable expiry are skipped. If RouterOS returned rows but
    // none was usable, the group is usable yet incomplete instead of a silent
    // empty Complete snapshot. Some usable rows are treated as complete so a
    // non-expiring certificate (for example a template) does not make the whole
    // router perpetually partial.
    let certificates_complete =
        certificates_are_complete(raw_certificate_rows, &certificates_result);

    let connection_failed = wireguard_peers_result
        .as_ref()
        .err()
        .is_some_and(crate::prelude::AppError::is_connection_level)
        || certificates_result
            .as_ref()
            .err()
            .is_some_and(crate::prelude::AppError::is_connection_level);
    client
        .record_group_result(&mut guard, connection_failed)
        .await;

    drop(guard);

    if wireguard_inconsistent {
        return Err(crate::prelude::AppError::InvalidSnapshot(
            SnapshotError::WireguardPeersCountMismatch,
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
        certificates_complete,
    })
}

/// A parsed certificate list is complete unless rows were returned while none
/// of them carried a usable expiry.
fn certificates_are_complete(raw_rows: usize, parsed: &Result<Vec<CertificateStats>>) -> bool {
    match parsed {
        Err(_) => false,
        Ok(certificates) => raw_rows == 0 || !certificates.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificates_complete_only_when_rows_are_usable() {
        let one = Ok(vec![CertificateStats::default()]);
        assert!(certificates_are_complete(1, &one));
        assert!(certificates_are_complete(0, &Ok(Vec::new())));
        // At least one usable row is complete, even if some rows were skipped.
        assert!(certificates_are_complete(3, &one));
        // Rows returned but none usable: incomplete, not a silent empty success.
        assert!(!certificates_are_complete(3, &Ok(Vec::new())));
        // A parse failure is never complete.
        assert!(!certificates_are_complete(
            1,
            &Err(crate::prelude::AppError::RouterOs("x".into()))
        ));
    }
}
