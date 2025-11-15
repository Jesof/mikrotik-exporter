//! Error types for the application

use std::fmt;

/// Application error type
#[derive(Debug)]
#[allow(dead_code)]
pub enum AppError {
    /// Configuration error
    Config(String),
    /// Network/IO error
    Io(std::io::Error),
    /// RouterOS API error
    RouterOs(String),
    /// Metrics encoding error
    Metrics(String),
    /// Address parsing error
    AddrParse(std::net::AddrParseError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "Configuration error: {}", msg),
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::RouterOs(msg) => write!(f, "RouterOS error: {}", msg),
            Self::Metrics(msg) => write!(f, "Metrics error: {}", msg),
            Self::AddrParse(e) => write!(f, "Address parse error: {}", e),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::AddrParse(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<std::net::AddrParseError> for AppError {
    fn from(error: std::net::AddrParseError) -> Self {
        Self::AddrParse(error)
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for AppError {
    fn from(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::RouterOs(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
