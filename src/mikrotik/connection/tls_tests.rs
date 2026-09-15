// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use super::{CONNECTION_TIMEOUT, ResponseBudget, RouterOsConnection};
use crate::AppError;
use crate::config::{Config, RouterConfig, RouterTlsConfig};
use crate::mikrotik::ConnectionPool;
use std::io::Write;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls};

fn certificate(names: Vec<String>) -> (TlsAcceptor, tempfile::NamedTempFile) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(names).unwrap();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(cert.pem().as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    (TlsAcceptor::from(Arc::new(config)), file)
}

async fn serve_router(listener: TcpListener, acceptor: TlsAcceptor) {
    let stream = acceptor
        .accept(listener.accept().await.unwrap().0)
        .await
        .unwrap();
    let mut peer = RouterOsConnection {
        stream: Box::new(stream),
        dirty: false,
    };
    for command in ["/login", "/system/resource/print"] {
        assert_eq!(
            peer.read_sentence(&mut ResponseBudget::default())
                .await
                .unwrap()
                .0,
            command
        );
        peer.send_words(&["!done".into()]).await.unwrap();
    }
}

#[tokio::test]
async fn test_tls_trusted_dns_and_ip_startup_authenticated_success() {
    for name in [Some("router.test"), None] {
        let (acceptor, ca) = certificate(vec!["router.test".into(), "127.0.0.1".into()]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = Config {
            routers: vec![RouterConfig {
                name: "tls-router".into(),
                address: listener.local_addr().unwrap().to_string(),
                username: "test-user".into(),
                password: "test-password".to_string().into(),
                tls: Some(RouterTlsConfig {
                    server_name: name.map(str::to_string),
                    ca_file: Some(ca.path().into()),
                }),
            }],
            ..Config::default()
        };
        let server = tokio::spawn(serve_router(listener, acceptor));
        assert!(config.test_router_connectivity(5).await.is_empty());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn test_tls_wrong_name_and_untrusted_certificate_rejected_before_login() {
    for wrong_name in [false, true] {
        let (acceptor, ca) = certificate(vec!["router.test".into()]);
        let (_, unrelated_ca) = certificate(vec!["unrelated.test".into()]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap().0;
            assert!(acceptor.accept(stream).await.is_err());
        });
        let tls = RouterTlsConfig {
            server_name: Some(
                if wrong_name {
                    "wrong.test"
                } else {
                    "router.test"
                }
                .into(),
            ),
            ca_file: Some(
                if wrong_name {
                    ca.path()
                } else {
                    unrelated_ca.path()
                }
                .into(),
            ),
        };
        let pool = ConnectionPool::new();
        assert!(matches!(
            pool.get_connection(&address, "test-user", "test-password", None, Some(&tls))
                .await,
            Err(AppError::Transport {
                operation: "TLS handshake",
                ..
            })
        ));
        assert_eq!(pool.get_pool_stats().await, (0, 0));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn test_tls_handshake_uses_total_connect_deadline() {
    let (_, ca) = certificate(vec!["router.test".into()]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (sent, received) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 22);
        sent.send(()).unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
    });
    let tls = RouterTlsConfig {
        server_name: Some("router.test".into()),
        ca_file: Some(ca.path().into()),
    };
    let connection = RouterOsConnection::connect(&address, Some(&tls));
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => panic!("TLS completed without a server handshake"),
        result = received => result.unwrap(),
    }
    tokio::time::pause();
    tokio::time::advance(CONNECTION_TIMEOUT).await;
    assert!(matches!(
        connection.await,
        Err(AppError::Timeout("connect"))
    ));
    tokio::time::resume();
    server.await.unwrap();
}

#[tokio::test]
async fn test_tls_never_reuses_idle_plaintext_connection() {
    let (acceptor, ca) = certificate(vec!["router.test".into()]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move {
        let mut plain = RouterOsConnection {
            stream: Box::new(listener.accept().await.unwrap().0),
            dirty: false,
        };
        assert_eq!(
            plain
                .read_sentence(&mut ResponseBudget::default())
                .await
                .unwrap()
                .0,
            "/login"
        );
        plain.send_words(&["!done".into()]).await.unwrap();
        serve_router(listener, acceptor).await;
    });
    let pool = ConnectionPool::new();
    drop(
        pool.get_connection(&address, "test-user", "test-password", None, None)
            .await
            .unwrap(),
    );
    let tls = RouterTlsConfig {
        server_name: Some("router.test".into()),
        ca_file: Some(ca.path().into()),
    };
    let mut guard = pool
        .get_connection(&address, "test-user", "test-password", None, Some(&tls))
        .await
        .unwrap();
    guard
        .get_mut()
        .command("/system/resource/print", &[])
        .await
        .unwrap();
    drop(guard);
    assert_eq!(pool.get_pool_stats().await, (2, 0));
    server.await.unwrap();
}

#[tokio::test]
async fn test_tls_invalid_or_empty_ca_fails_closed() {
    for contents in [
        "",
        "not PEM",
        "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
    ] {
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(contents.as_bytes()).unwrap();
        let tls = RouterTlsConfig {
            server_name: None,
            ca_file: Some(ca.path().into()),
        };
        assert!(super::tls::connector(&tls).await.is_err());
    }
}

#[tokio::test]
async fn test_tls_changed_name_or_ca_cannot_reuse_trusted_connection() {
    for change_ca in [false, true] {
        let (acceptor, ca) = certificate(vec!["router.test".into()]);
        let (_, unrelated) = certificate(vec!["other.test".into()]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let stream = acceptor
                .accept(listener.accept().await.unwrap().0)
                .await
                .unwrap();
            let mut peer = RouterOsConnection {
                stream: Box::new(stream),
                dirty: false,
            };
            assert_eq!(
                peer.read_sentence(&mut ResponseBudget::default())
                    .await
                    .unwrap()
                    .0,
                "/login"
            );
            peer.send_words(&["!done".into()]).await.unwrap();
            assert!(
                acceptor
                    .accept(listener.accept().await.unwrap().0)
                    .await
                    .is_err()
            );
            assert!(
                acceptor
                    .accept(listener.accept().await.unwrap().0)
                    .await
                    .is_err()
            );
            assert_eq!(
                peer.read_sentence(&mut ResponseBudget::default())
                    .await
                    .unwrap()
                    .0,
                "/reused"
            );
            peer.send_words(&["!done".into()]).await.unwrap();
        });
        let tls = RouterTlsConfig {
            server_name: Some("router.test".into()),
            ca_file: Some(ca.path().into()),
        };
        let pool = ConnectionPool::new();
        drop(
            pool.get_connection(&address, "test-user", "test-password", None, Some(&tls))
                .await
                .unwrap(),
        );
        let mut changed = tls.clone();
        if change_ca {
            changed.ca_file = Some(unrelated.path().into());
        } else {
            changed.server_name = Some("wrong.test".into());
        }
        for _ in 0..2 {
            assert!(matches!(
                pool.get_connection(&address, "test-user", "test-password", None, Some(&changed))
                    .await,
                Err(AppError::Transport {
                    operation: "TLS handshake",
                    ..
                })
            ));
        }
        let mut guard = pool
            .get_connection(&address, "test-user", "test-password", None, Some(&tls))
            .await
            .unwrap();
        guard.get_mut().command("/reused", &[]).await.unwrap();
        server.await.unwrap();
    }
}

#[tokio::test]
async fn test_startup_reports_tls_verification_failure() {
    let (acceptor, ca) = certificate(vec!["router.test".into()]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = Config {
        routers: vec![RouterConfig {
            name: "tls-router".into(),
            address: listener.local_addr().unwrap().to_string(),
            username: "test-user".into(),
            password: "test-password".to_string().into(),
            tls: Some(RouterTlsConfig {
                server_name: Some("wrong.test".into()),
                ca_file: Some(ca.path().into()),
            }),
        }],
        ..Config::default()
    };
    let server = tokio::spawn(async move {
        assert!(
            acceptor
                .accept(listener.accept().await.unwrap().0)
                .await
                .is_err()
        );
    });
    assert_eq!(config.test_router_connectivity(5).await, vec!["tls-router"]);
    server.await.unwrap();
}
