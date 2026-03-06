// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Grouped collection implementations for router metric collection.

use crate::mikrotik::client::MikroTikClient;
use crate::prelude::Result;

mod common;
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
    group.as_ref().map(Result::is_ok).unwrap_or(false)
}

pub(crate) fn failed_group_names(groups: &[(&'static str, bool)]) -> Vec<&'static str> {
    groups
        .iter()
        .filter_map(|(name, ok)| (!*ok).then_some(*name))
        .collect()
}

pub(crate) fn inconsistent_snapshot_error<T>(
    group: &std::result::Result<Result<T>, tokio::time::error::Elapsed>,
) -> Option<&str> {
    if let Ok(Err(crate::prelude::AppError::RouterOs(message))) = group
        && message.contains("inconsistent snapshot")
    {
        return Some(message.as_str());
    }
    None
}
