//! Error types for the application

use thiserror::Error;

/// Application error type
#[derive(Debug, Error)]
pub enum AppError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Network/IO error
    #[error("IO error")]
    Io(#[from] std::io::Error),

    /// `RouterOS` API error
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

/// Type alias for `Result` with `AppError`
pub type Result<T> = std::result::Result<T, AppError>;
