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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_error() {
        let err = AppError::Config("test error".to_string());
        assert_eq!(err.to_string(), "Configuration error: test error");
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
