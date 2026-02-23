// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! `RouterOS` API response parsing modules
//!
//! This module contains parsers for different types of data returned
//! by the `RouterOS` API, such as system resources, interfaces, connection
//! tracking, `WireGuard`, and certificates.

pub(crate) mod certificates;
pub(crate) mod conntrack;
pub(crate) mod firewall;
pub(crate) mod interfaces;
pub(crate) mod system;
pub(crate) mod wireguard;

pub(crate) use certificates::parse_certificates;
pub(crate) use conntrack::parse_connection_tracking;
pub(crate) use firewall::parse_firewall_rules;
pub(crate) use interfaces::parse_interfaces;
pub(crate) use system::parse_system;
pub(crate) use wireguard::parse_wireguard_peers;
