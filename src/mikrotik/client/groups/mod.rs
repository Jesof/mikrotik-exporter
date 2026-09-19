// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Grouped collection implementations for router metric collection.

use crate::mikrotik::{MikroTikClient, SnapshotError};
use crate::prelude::Result;

mod conntrack;
mod firewall;
mod system;
mod vpn;

pub(crate) async fn collect_group_system_interfaces(
    client: &MikroTikClient,
) -> Result<super::SystemInterfacesGroupData> {
    system::collect_group_system_interfaces(client).await
}

pub(crate) async fn collect_group_conntrack(
    client: &MikroTikClient,
) -> Result<super::ConntrackGroupData> {
    conntrack::collect_group_conntrack(client).await
}

pub(crate) async fn collect_group_vpn_certs(
    client: &MikroTikClient,
) -> Result<super::VpnCertGroupData> {
    vpn::collect_group_vpn_certs(client).await
}

pub(crate) async fn collect_group_firewall(
    client: &MikroTikClient,
) -> Result<super::FirewallGroupData> {
    firewall::collect_group_firewall(client).await
}

pub(crate) fn timeout_group_ok<T>(
    group: &std::result::Result<Result<T>, tokio::time::error::Elapsed>,
) -> bool {
    group.as_ref().is_ok_and(Result::is_ok)
}

pub(crate) fn failed_group_names(groups: &[(&'static str, bool)]) -> Vec<&'static str> {
    groups
        .iter()
        .filter_map(|(name, ok)| (!*ok).then_some(*name))
        .collect()
}

pub(crate) fn inconsistent_snapshot_error<T>(
    group: &std::result::Result<Result<T>, tokio::time::error::Elapsed>,
) -> Option<&SnapshotError> {
    if let Ok(Err(crate::prelude::AppError::InvalidSnapshot(error))) = group {
        return Some(error);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::AppError;

    #[test]
    fn test_snapshot_error_classification_uses_variant() {
        let invalid: std::result::Result<Result<()>, tokio::time::error::Elapsed> = Ok(Err(
            AppError::InvalidSnapshot(SnapshotError::GenericMessage("bad number".into())),
        ));
        assert!(
            matches!(inconsistent_snapshot_error(&invalid), Some(SnapshotError::GenericMessage(message)) if message == "bad number")
        );
        let other: std::result::Result<Result<()>, tokio::time::error::Elapsed> =
            Ok(Err(AppError::RouterOs("inconsistent snapshot".into())));
        assert_eq!(inconsistent_snapshot_error(&other), None);
    }
}
