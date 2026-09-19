// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Error types for `MikroTik` Exporter application

use crate::config::ConfigError;
use thiserror::Error;

/// Main application error type
#[derive(Error)]
pub enum AppError {
    /// Configuration error
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// Network or IO error
    #[error("IO error")]
    Io(#[from] std::io::Error),

    /// `RouterOS` API error
    #[error("RouterOS error: {0}")]
    RouterOs(String),

    /// Parsed router snapshot is inconsistent or malformed
    #[error("Invalid router snapshot: {0}")]
    InvalidSnapshot(String),

    /// `RouterOS` protocol framing or sentence violation
    #[error("RouterOS protocol error: {0}")]
    Protocol(String),

    /// Transport-level failure during a `RouterOS` operation
    #[error("RouterOS transport error during {operation}: {source}")]
    Transport {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// Operation did not complete within its deadline
    #[error("RouterOS timeout during {0}")]
    Timeout(&'static str),

    /// `RouterOS` rejected the command with a trap sentence
    #[error("RouterOS command rejected (category {category:?})")]
    RouterOsTrap {
        category: Option<u8>,
        message: String,
    },

    /// `RouterOS` closed the connection without a clean reply
    #[error("RouterOS terminated the connection")]
    RouterOsFatal,

    /// Credentials or challenge were rejected by the router
    #[error("RouterOS authentication failed: {0}")]
    Authentication(String),

    /// Metrics encoding error
    #[error("Metrics error: {0}")]
    Metrics(String),

    /// Address parsing error
    #[error("Address parse error")]
    AddrParse(#[from] std::net::AddrParseError),
}

impl AppError {
    /// Whether this error means the pooled connection itself is unusable.
    ///
    /// Connection-level failures (I/O, timeouts, protocol desync, fatal or
    /// authentication rejection) must discard the connection and count toward
    /// pool backoff. Query-level failures (a `!trap` for an unsupported table,
    /// or an invalid snapshot) leave a protocol-clean connection reusable and
    /// must not drive backoff.
    pub(crate) fn is_connection_level(&self) -> bool {
        matches!(
            self,
            Self::Io(_)
                | Self::Transport { .. }
                | Self::Timeout(_)
                | Self::Protocol(_)
                | Self::RouterOsFatal
                | Self::Authentication(_)
        )
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for AppError {
    fn from(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::RouterOs(error.to_string())
    }
}

impl std::fmt::Debug for AppError {
    /// Delegates to the human-readable `Display` message.
    ///
    /// The binary prints `std::result::Result` terminal errors with `Debug`,
    /// so hiding the structured variants behind the message keeps operator
    /// output readable.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

/// Convenient alias for Result with application error
pub type Result<T> = std::result::Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_error() {
        let err = AppError::Config(ConfigError::InvalidServerAddr);
        assert_eq!(err.to_string(), "SERVER_ADDR must be an IP socket address");
    }

    #[test]
    fn test_router_os_error() {
        let err = AppError::RouterOs("connection failed".to_string());
        assert_eq!(err.to_string(), "RouterOS error: connection failed");
    }

    #[test]
    fn test_metrics_error() {
        let err = AppError::Metrics("encoding failed".to_string());
        assert_eq!(err.to_string(), "Metrics error: encoding failed");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let app_err: AppError = io_err.into();
        assert!(matches!(app_err, AppError::Io(_)));
    }

    #[test]
    fn test_addr_parse_error_conversion() {
        let parse_result = "invalid".parse::<std::net::IpAddr>();
        assert!(parse_result.is_err());
        let app_err: AppError = parse_result.unwrap_err().into();
        assert!(matches!(app_err, AppError::AddrParse(_)));
    }

    #[test]
    fn test_boxed_error_conversion() {
        let boxed_err: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::other("test"));
        let app_err: AppError = boxed_err.into();
        assert!(matches!(app_err, AppError::RouterOs(_)));
    }
}
