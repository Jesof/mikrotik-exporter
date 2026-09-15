// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use crate::config::RouterTlsConfig;
use crate::prelude::{AppError, Result};
use std::sync::Arc;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore,
    crypto::ring,
    pki_types::{CertificateDer, pem::PemObject},
};

pub(super) async fn connector(tls: &RouterTlsConfig) -> Result<TlsConnector> {
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
                certificate.map_err(|_| AppError::Config("Invalid TLS CA PEM".into()))?;
            roots
                .add(certificate)
                .map_err(|_| AppError::Config("Invalid TLS CA certificate".into()))?;
        }
    } else {
        let native = tokio::task::spawn_blocking(rustls_native_certs::load_native_certs)
            .await
            .map_err(|_| AppError::Config("Unable to load system TLS roots".into()))?;
        roots.add_parsable_certificates(native.certs);
    }
    if roots.is_empty() {
        return Err(AppError::Config(
            "TLS trust store contains no usable certificates".into(),
        ));
    }
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| AppError::Config("Unable to configure TLS protocol versions".into()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}
