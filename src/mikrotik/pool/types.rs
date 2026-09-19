// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Internal connection-pool types and state helpers.

use std::time::Duration;

use crate::mikrotik::connection::RouterOsConnection;

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct ConnectionKey {
    pub(super) address: String,
    pub(super) username: String,
    pub(super) credential: Credential,
    pub(super) group: Option<String>,
    pub(super) tls: Option<crate::config::RouterTlsConfig>,
}

// Keep credential identity opaque in diagnostics and zeroized when the key is dropped.
#[derive(Clone)]
pub(super) struct Credential(secrecy::SecretString);

impl From<&str> for Credential {
    fn from(password: &str) -> Self {
        Self(password.to_owned().into())
    }
}

impl Credential {
    /// Compare against a plaintext password without exposing the stored secret.
    pub(super) fn matches(&self, password: &str) -> bool {
        use secrecy::ExposeSecret;
        self.0.expose_secret() == password
    }
}

impl ConnectionKey {
    /// Whether the key matches a router's full connection identity
    /// (address, username, password, and TLS settings), ignoring the group.
    ///
    /// Used for state cleanup so entries keyed by a stale credential or TLS
    /// profile are not retained when only the address and username match.
    pub(super) fn matches_identity(
        &self,
        address: &str,
        username: &str,
        password: &str,
        tls: Option<&crate::config::RouterTlsConfig>,
    ) -> bool {
        self.address == address
            && self.username == username
            && self.credential.matches(password)
            && self.tls.as_ref() == tls
    }
}

impl PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        use secrecy::ExposeSecret;
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Eq for Credential {}

impl std::hash::Hash for Credential {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        use secrecy::ExposeSecret;
        self.0.expose_secret().hash(state);
    }
}

impl std::fmt::Display for ConnectionKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} (TLS: {})", self.address, self.tls.is_some())
    }
}

pub(super) mod timeouts {
    use std::time::Duration;

    /// Maximum idle time before connection is closed (5 minutes)
    pub const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

    /// Maximum backoff duration (5 minutes)
    pub const MAX_BACKOFF: Duration = Duration::from_secs(300);
}

pub(super) mod backoff {
    use std::time::Duration;

    /// Minimum consecutive errors before backoff applies
    pub const MIN_ERRORS_FOR_BACKOFF: u32 = 2;

    /// Error threshold for long backoff period
    pub const LONG_BACKOFF_ERROR_THRESHOLD: u32 = 6;

    /// Long backoff duration after many consecutive errors
    pub const LONG_BACKOFF_DURATION: Duration = Duration::from_secs(45);

    /// Maximum exponent for exponential backoff (2^6 = 64 seconds)
    pub const MAX_BACKOFF_EXPONENT: u32 = 6;
}

pub(super) struct PooledConnection {
    pub(super) connection: RouterOsConnection,
    pub(super) last_used: tokio::time::Instant,
}

/// Tracks connection health and error state.
#[derive(Clone)]
pub(super) struct ConnectionState {
    pub(super) consecutive_errors: u32,
    pub(super) last_error_time: Option<tokio::time::Instant>,
    pub(super) last_success_time: Option<tokio::time::Instant>,
}

impl ConnectionState {
    pub(super) fn new() -> Self {
        Self {
            consecutive_errors: 0,
            last_error_time: None,
            last_success_time: None,
        }
    }

    pub(super) fn record_success(&mut self) {
        self.consecutive_errors = 0;
        self.last_success_time = Some(tokio::time::Instant::now());
    }

    pub(super) fn record_error(&mut self) {
        self.consecutive_errors = self.consecutive_errors.saturating_add(1);
        self.last_error_time = Some(tokio::time::Instant::now());
    }

    pub(super) fn backoff_delay(&self) -> Duration {
        // Exponential backoff: 2^n seconds, capped by configured maximum.
        let base_delay = 2u64.pow(self.consecutive_errors.min(backoff::MAX_BACKOFF_EXPONENT));
        let max_secs = timeouts::MAX_BACKOFF.as_secs();
        Duration::from_secs(base_delay.min(max_secs))
    }

    pub(super) fn retry_delay(&self) -> Duration {
        if self.consecutive_errors >= backoff::LONG_BACKOFF_ERROR_THRESHOLD {
            backoff::LONG_BACKOFF_DURATION
        } else {
            self.backoff_delay()
        }
    }

    pub(super) fn remaining_retry_delay(&self) -> Duration {
        if let Some(last_error) = self.last_error_time {
            self.retry_delay().saturating_sub(last_error.elapsed())
        } else {
            self.retry_delay()
        }
    }

    pub(super) fn should_skip_attempt(&self) -> bool {
        if self.consecutive_errors < backoff::MIN_ERRORS_FOR_BACKOFF {
            return false;
        }

        if let Some(last_error) = self.last_error_time {
            last_error.elapsed() < self.retry_delay()
        } else {
            false
        }
    }
}
