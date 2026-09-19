// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Registry initialization: delegates to domain modules.

use prometheus_client::registry::Registry;

use super::{
    CertificateDomain, ConntrackDomain, FirewallDomain, InterfaceDomain, MetricsRegistry,
    PoolDomain, ScrapeDomain, SystemDomain, WireGuardDomain,
};

impl MetricsRegistry {
    #[allow(clippy::similar_names)]
    #[must_use]
    /// Creates an empty registry with all metric families registered.
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let interface = InterfaceDomain::new(&mut registry);
        let firewall = FirewallDomain::new(&mut registry);
        let system = SystemDomain::new(&mut registry);
        let scrape = ScrapeDomain::new(&mut registry);
        let pool = PoolDomain::new(&mut registry);
        let conntrack = ConntrackDomain::new(&mut registry);
        let wireguard = WireGuardDomain::new(&mut registry);
        let certificate = CertificateDomain::new(&mut registry);

        Self {
            registry: std::sync::Arc::new(tokio::sync::Mutex::new(registry)),
            interface,
            system,
            conntrack,
            wireguard,
            certificate,
            firewall,
            scrape,
            pool,
            known_routers: std::sync::Arc::new(dashmap::DashMap::new()),
        }
    }
}
