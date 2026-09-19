// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Typed configuration and router validation errors.
//!
//! These types give operators and library callers a structured way to
//! distinguish configuration failures (bad JSON, invalid addresses, duplicate
//! names, out-of-range settings) instead of matching on free-form text.

use thiserror::Error;

/// Router-level configuration validation error.
///
/// Covers a single router entry: name, address, username, and TLS settings.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RouterError {
    /// TLS address is missing the required `host:port` form.
    #[error("Invalid TLS router address")]
    InvalidTlsAddress,

    /// `server_name` cannot be turned into a verified TLS identity.
    #[error("Invalid TLS server name")]
    InvalidTlsServerName,

    /// `ca_file` path is present but empty.
    #[error("TLS CA file path cannot be empty")]
    EmptyCaFile,

    /// Router name is blank.
    #[error("Router name cannot be empty")]
    EmptyName,

    /// Router name contains characters other than ASCII alphanumeric, `_`, or `-`.
    #[error(
        "Router name '{name}' contains invalid characters. Only alphanumeric, underscore, and hyphen are allowed"
    )]
    InvalidNameChars {
        /// Offending router name.
        name: String,
    },

    /// Router name exceeds 128 characters.
    #[error("Router name is too long: maximum length is 128 characters")]
    NameTooLong,

    /// Address is missing the required `host:port` separator.
    #[error("Invalid address format '{address}': expected 'host:port'")]
    InvalidAddressFormat {
        /// Offending address.
        address: String,
    },

    /// Address host is empty (`:port`).
    #[error("Invalid address format '{address}': host cannot be empty")]
    EmptyAddressHost {
        /// Offending address.
        address: String,
    },

    /// IPv6 host is not wrapped in brackets.
    #[error("Invalid IPv6 address format '{address}': expected '[addr]:port'")]
    InvalidIpv6Format {
        /// Offending address.
        address: String,
    },

    /// Bracketed host is not a valid IPv6 address.
    #[error("Invalid IPv6 address")]
    InvalidIpv6Address,

    /// IPv6 host is present without surrounding brackets.
    #[error("Invalid IPv6 address format '{address}': wrap IPv6 hosts in brackets")]
    UnbracketedIpv6 {
        /// Offending address.
        address: String,
    },

    /// Hostname labels are malformed.
    #[error("Invalid router hostname")]
    InvalidHostname,

    /// Port is `0`.
    #[error("Invalid port number in address '{address}': port cannot be 0")]
    ZeroPort {
        /// Offending address.
        address: String,
    },

    /// Port is not a numeric value in 1-65535.
    #[error("Invalid port number in address '{address}': expected numeric value 1-65535")]
    InvalidPort {
        /// Offending address.
        address: String,
    },

    /// Address exceeds 253 characters.
    #[error("Address '{address}' is too long: maximum length is 253 characters")]
    AddressTooLong {
        /// Offending address.
        address: String,
    },

    /// Username is blank.
    #[error("Username cannot be empty for router '{name}'")]
    EmptyUsername {
        /// Router name the username belongs to.
        name: String,
    },

    /// Username exceeds 64 bytes.
    #[error("Username for router '{name}' is too long: maximum length is 64 characters")]
    UsernameTooLong {
        /// Router name the username belongs to.
        name: String,
    },
}

/// Application-wide configuration error.
///
/// Used as the payload of [`crate::AppError::Config`]:
/// - malformed environment/JSON values,
/// - invalid server address or out-of-range settings,
/// - unsupported command-line arguments,
/// - strict-mode startup constraints,
/// - per-router validation failures ([`RouterError`]),
/// - TLS trust-store loading failures.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// `ROUTERS_CONFIG` JSON did not parse.
    #[error("Invalid {key} JSON at line {line}, column {column}")]
    InvalidRoutersJson {
        /// Environment variable name.
        key: String,
        /// serde error line.
        line: usize,
        /// serde error column.
        column: usize,
    },

    /// `ROUTEROS_TLS` legacy JSON did not parse.
    #[error("Invalid {key} JSON")]
    InvalidJson {
        /// Environment variable name.
        key: String,
    },

    /// An environment variable is not a valid value for its type.
    #[error("Invalid {key}")]
    InvalidValue {
        /// Environment variable name.
        key: String,
    },

    /// Environment variable contains non-Unicode bytes.
    #[error("Invalid Unicode in {key}")]
    InvalidUnicode {
        /// Environment variable name.
        key: String,
    },

    /// `SERVER_ADDR` is not an IP socket address.
    #[error("SERVER_ADDR must be an IP socket address")]
    InvalidServerAddr,

    /// A numeric setting is outside its documented range.
    #[error("{key} must be between 1 and {maximum}")]
    OutOfRange {
        /// Environment variable name.
        key: String,
        /// Documented maximum.
        maximum: u64,
    },

    /// Strict mode requires the startup connectivity test.
    #[error("STRICT_STARTUP_MODE requires STARTUP_CONNECTIVITY_TEST=true")]
    StrictRequiresConnectivityTest,

    /// Strict mode requires at least one configured router.
    #[error("STRICT_STARTUP_MODE requires at least one router")]
    StrictRequiresRouter,

    /// Duplicate router names are rejected.
    #[error("Duplicate router name '{name}'")]
    DuplicateRouterName {
        /// Offending router name.
        name: String,
    },

    /// Strict mode startup found unreachable routers.
    #[error("Strict startup mode: {count} router(s) unreachable: {routers:?}")]
    StrictUnreachable {
        /// Number of failed routers.
        count: usize,
        /// Failed router names.
        routers: Vec<String>,
    },

    /// Command-line arguments other than `--version`/`-V` are rejected.
    #[error("Unsupported arguments; use --version or configure via environment variables")]
    UnsupportedArguments,

    /// Per-router validation failure.
    #[error(transparent)]
    Router(#[from] RouterError),

    /// TLS trust-store configuration failure.
    #[error(transparent)]
    Tls(#[from] TlsError),
}

/// TLS trust-store configuration error.
///
/// These are configuration-time failures surfaced while building the verified
/// TLS connector for a router.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// CA file is not valid PEM.
    #[error("Invalid TLS CA PEM")]
    InvalidCaPem,

    /// CA PEM does not parse as a certificate.
    #[error("Invalid TLS CA certificate")]
    InvalidCaCertificate,

    /// System trust roots could not be loaded.
    #[error("Unable to load system TLS roots")]
    SystemRootsUnavailable,

    /// The trust store contains no usable certificates.
    #[error("TLS trust store contains no usable certificates")]
    EmptyTrustStore,

    /// TLS protocol version configuration failed.
    #[error("Unable to configure TLS protocol versions")]
    ProtocolConfiguration,
}
