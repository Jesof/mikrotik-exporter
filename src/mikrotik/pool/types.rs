// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Internal connection-pool types and state helpers.

use std::time::Duration;

use crate::mikrotik::connection::RouterOsConnection;

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
