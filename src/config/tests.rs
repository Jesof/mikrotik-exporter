// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use super::{Config, RouterConfig};
use secrecy::ExposeSecret;

fn load(values: &[(&str, &str)]) -> crate::Result<Config> {
    Config::from_lookup(|key| {
        Ok(values
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| (*value).into()))
    })
}

#[test]
fn test_missing_values_use_defaults() {
    let config = load(&[]).unwrap();
    assert_eq!(config.server_addr, "0.0.0.0:9090");
    assert_eq!(config.collection_interval_secs, 30);
    assert_eq!(config.gap_reset_threshold_secs, 60);
    assert_eq!(config.startup_connectivity_timeout_secs, 10);
    assert!(config.routers.is_empty());
    assert!(!config.startup_connectivity_test);
    assert!(!config.strict_startup_mode);
}

#[test]
fn test_tls_configuration_is_opt_in_and_rejects_insecure_options() {
    let router = r#"{"name":"edge","address":"localhost:8729","username":"admin","password":"test-password"}"#;
    let load_tls = |tls: &str| {
        load(&[(
            "ROUTERS_CONFIG",
            &format!("[{},\"tls\":{tls}}}]", &router[..router.len() - 1]),
        )])
    };
    assert!(
        load(&[("ROUTERS_CONFIG", &format!("[{router}]"))])
            .unwrap()
            .routers[0]
            .tls
            .is_none()
    );
    assert_eq!(
        load_tls("{}").unwrap().routers[0].tls,
        Some(super::RouterTlsConfig::default())
    );
    for tls in [
        "false",
        r#"{"insecure":true}"#,
        r#"{"enabled":false}"#,
        r#"{"server_name":""}"#,
        r#"{"server_name":"https://router"}"#,
        r#"{"ca_file":""}"#,
    ] {
        assert!(load_tls(tls).is_err(), "{tls}");
    }
    assert!(
        load(&[
            ("ROUTEROS_ADDRESS", "localhost:8729"),
            ("ROUTEROS_TLS", "{}")
        ])
        .unwrap()
        .routers[0]
            .tls
            .is_some()
    );
    assert!(
        load(&[
            ("ROUTEROS_ADDRESS", "localhost:8729"),
            ("ROUTEROS_TLS", "false")
        ])
        .is_err()
    );
}

#[test]
fn test_tls_server_names_preserve_ip_and_dns_identity() {
    use tokio_rustls::rustls::pki_types::ServerName;
    let tls = super::RouterTlsConfig::default();
    for address in ["127.0.0.1:8729", "[::1]:8729", "[2001:db8::1]:8729"] {
        assert!(matches!(
            tls.server_name_for_address(address).unwrap(),
            ServerName::IpAddress(_)
        ));
    }
    assert!(matches!(
        tls.server_name_for_address("router.test:8729").unwrap(),
        ServerName::DnsName(_)
    ));
}

#[test]
fn test_invalid_numeric_values_fail_instead_of_defaulting() {
    for key in [
        "COLLECTION_INTERVAL_SECONDS",
        "GAP_RESET_THRESHOLD_SECONDS",
        "STARTUP_CONNECTIVITY_TIMEOUT_SECS",
    ] {
        for value in [
            "",
            "bad",
            "-1",
            "1.5",
            "0",
            "18446744073709551615",
            "18446744073709551616",
        ] {
            let error = load(&[(key, value)]).unwrap_err().to_string();
            assert!(error.contains(key), "{key}={value}: {error}");
        }
    }
}

#[test]
fn test_duration_bounds() {
    for (key, maximum) in [
        ("COLLECTION_INTERVAL_SECONDS", 86_400),
        ("GAP_RESET_THRESHOLD_SECONDS", 604_800),
        ("STARTUP_CONNECTIVITY_TIMEOUT_SECS", 300),
    ] {
        assert!(load(&[(key, "1")]).is_ok());
        assert!(load(&[(key, &maximum.to_string())]).is_ok());
        assert!(load(&[(key, &(maximum + 1).to_string())]).is_err());
    }
}

#[test]
fn test_invalid_boolean_and_unicode_fail() {
    for key in ["STARTUP_CONNECTIVITY_TEST", "STRICT_STARTUP_MODE"] {
        assert!(load(&[(key, "yes")]).is_err());
    }
    assert!(
        Config::from_lookup(|_| Err(crate::AppError::Config(
            crate::ConfigError::InvalidUnicode { key: "TEST".into() }
        )))
        .is_err()
    );
}

#[test]
fn test_invalid_json_never_falls_back_or_exposes_contents() {
    for json in ["secret-not-json", r#"[{"name":"r","password":123456789}]"#] {
        let error = load(&[
            ("ROUTERS_CONFIG", json),
            ("ROUTEROS_ADDRESS", "localhost:8728"),
        ])
        .unwrap_err()
        .to_string();
        assert!(error.contains("ROUTERS_CONFIG"));
        assert!(!error.contains("secret-not-json"));
        assert!(!error.contains("123456789"));
    }
}

#[test]
fn test_json_router_validation_and_unique_names() {
    let router =
        r#"{"name":"edge","address":"localhost:8728","username":"admin","password":"secret"}"#;
    let config = load(&[("ROUTERS_CONFIG", &format!("[{router}]"))]).unwrap();
    assert_eq!(config.routers[0].name, "edge");
    assert_eq!(config.routers[0].password.expose_secret(), "secret");
    assert!(
        load(&[("ROUTERS_CONFIG", &format!("[{router},{router}]"))])
            .unwrap_err()
            .to_string()
            .contains("Duplicate")
    );
    assert!(
        load(&[(
            "ROUTERS_CONFIG",
            &format!("[{}]", router.replace("edge", "bad name"))
        )])
        .is_err()
    );
    assert!(
        load(&[(
            "ROUTERS_CONFIG",
            &format!("[{}]", router.replace("\"name\"", "\"typo\""))
        )])
        .is_err()
    );
}

#[test]
fn test_legacy_credentials_and_json_precedence() {
    let config = load(&[("ROUTEROS_ADDRESS", "localhost:8728")]).unwrap();
    assert_eq!(config.routers[0].name, "default");
    assert_eq!(config.routers[0].username, "admin");
    assert_eq!(config.routers[0].password.expose_secret(), "");
    let config = load(&[
        ("ROUTEROS_ADDRESS", "localhost:8728"),
        ("ROUTEROS_USERNAME", "reader"),
        ("ROUTEROS_PASSWORD", "example"),
    ])
    .unwrap();
    assert_eq!(config.routers[0].username, "reader");
    assert_eq!(config.routers[0].password.expose_secret(), "example");
    assert!(
        load(&[
            ("ROUTERS_CONFIG", "[]"),
            ("ROUTEROS_ADDRESS", "localhost:8728")
        ])
        .unwrap()
        .routers
        .is_empty()
    );
}

#[test]
fn test_strict_startup_requires_checks_and_routers() {
    assert!(load(&[("STRICT_STARTUP_MODE", "true")]).is_err());
    assert!(
        load(&[
            ("STRICT_STARTUP_MODE", "true"),
            ("STARTUP_CONNECTIVITY_TEST", "true")
        ])
        .is_err()
    );
    assert!(
        load(&[
            ("STRICT_STARTUP_MODE", "true"),
            ("STARTUP_CONNECTIVITY_TEST", "true"),
            ("ROUTEROS_ADDRESS", "localhost:8728")
        ])
        .is_ok()
    );
}

#[test]
fn test_address_validation() {
    let mut router = RouterConfig {
        name: "edge-01_a".into(),
        address: String::new(),
        username: "admin".into(),
        password: String::new().into(),
        tls: None,
    };
    for address in [
        "localhost:8728",
        "192.168.1.1:8728",
        "[2001:db8::1]:8728",
        "router.example.:8728",
    ] {
        router.address = address.into();
        assert!(router.validate().is_ok(), "{address}");
    }
    for address in [
        "localhost",
        ":8728",
        "localhost:0",
        "localhost:65536",
        "localhost:abc",
        "[garbage]:8728",
        "2001:db8::1:8728",
        "bad host:8728",
        "-bad:8728",
        "a..b:8728",
        "http://router:8728",
    ] {
        router.address = address.into();
        assert!(router.validate().is_err(), "{address}");
    }
    assert!(load(&[("SERVER_ADDR", "garbage")]).is_err());
}
