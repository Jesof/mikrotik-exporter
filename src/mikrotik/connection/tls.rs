// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! `RouterOS` TLS connector with root store loading and server-name identity.

use dashmap::DashMap;
use std::sync::{Arc, OnceLock};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore,
    crypto::ring,
    pki_types::{CertificateDer, pem::PemObject},
};

use crate::config::{RouterTlsConfig, TlsError};
use crate::prelude::{AppError, Result};

/// Process-wide cache of verified TLS connectors keyed by router TLS settings.
///
/// Building the connector loads the trust store (including system roots from
/// disk); caching keeps that out of the per-connection connect deadline and
/// avoids repeating it on every reconnect. Configuration changes require a
/// restart, matching the documented configuration model.
fn connector_cache() -> &'static DashMap<RouterTlsConfig, TlsConnector> {
    static CACHE: OnceLock<DashMap<RouterTlsConfig, TlsConnector>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

pub(super) async fn connector(tls: &RouterTlsConfig) -> Result<TlsConnector> {
    if let Some(cached) = connector_cache().get(tls) {
        return Ok(cached.clone());
    }
    let connector = build_connector(tls).await?;
    connector_cache().insert(tls.clone(), connector.clone());
    Ok(connector)
}

async fn build_connector(tls: &RouterTlsConfig) -> Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = &tls.ca_file {
        let pem = tokio::fs::read(path)
            .await
            .map_err(|source| AppError::Transport {
                operation: "read TLS CA file",
                source,
            })?;
        for certificate in CertificateDer::pem_slice_iter(&pem) {
            let certificate =
                certificate.map_err(|_| AppError::Config(TlsError::InvalidCaPem.into()))?;
            roots
                .add(certificate)
                .map_err(|_| AppError::Config(TlsError::InvalidCaCertificate.into()))?;
        }
    } else {
        let native = tokio::task::spawn_blocking(rustls_native_certs::load_native_certs)
            .await
            .map_err(|_| AppError::Config(TlsError::SystemRootsUnavailable.into()))?;
        roots.add_parsable_certificates(native.certs);
    }
    if roots.is_empty() {
        return Err(AppError::Config(TlsError::EmptyTrustStore.into()));
    }
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| AppError::Config(TlsError::ProtocolConfiguration.into()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}
