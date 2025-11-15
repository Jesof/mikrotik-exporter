//! Error types for MikroTik Exporter application

use thiserror::Error;

/// Main application error type
#[derive(Debug, Error)]
pub enum AppError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Network or IO error
    #[error("IO error")]
    Io(#[from] std::io::Error),

    /// RouterOS API error
    #[error("RouterOS error: {0}")]
    RouterOs(String),

    /// Metrics encoding error
    #[error("Metrics error: {0}")]
    Metrics(String),

    /// Address parsing error
    #[error("Address parse error")]
    AddrParse(#[from] std::net::AddrParseError),
}

impl From<Box<dyn std::error::Error + Send + Sync>> for AppError {
    fn from(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::RouterOs(error.to_string())
    }
}

/// Convenient alias for Result with application error
pub type Result<T> = std::result::Result<T, AppError>;
