//! Application state shared across HTTP handlers

use crate::config::Config;
use crate::metrics::MetricsRegistry;

/// Shared application state
pub struct AppState {
    pub config: Config,
    pub metrics: MetricsRegistry,
}
