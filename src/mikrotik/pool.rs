// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Connection pool for managing RouterOS connections

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};

use super::connection::RouterOsConnection;

/// Connection pool configuration constants
mod timeouts {
    use std::time::Duration;

    /// Maximum idle time before connection is closed (5 minutes)
    pub const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

    /// Maximum backoff duration (5 minutes)
    pub const MAX_BACKOFF: Duration = Duration::from_secs(300);
}

/// Backoff strategy configuration
mod backoff {
    use std::time::Duration;

    /// Minimum consecutive errors before backoff applies
    pub const MIN_ERRORS_FOR_BACKOFF: u32 = 3;

    /// Error threshold for long backoff period (1 hour)
    pub const LONG_BACKOFF_ERROR_THRESHOLD: u32 = 10;

    /// Long backoff duration after many consecutive errors (1 hour)
    pub const LONG_BACKOFF_DURATION: Duration = Duration::from_secs(3600);

    /// Maximum exponent for exponential backoff (2^8 = 256 seconds)
    pub const MAX_BACKOFF_EXPONENT: u32 = 8;
}

/// Connection pool for reusing `RouterOS` connections
#[derive(Clone)]
pub struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, PooledConnection>>>,
    connection_states: Arc<Mutex<HashMap<String, ConnectionState>>>,
    max_idle_time: Duration,
    return_tx: mpsc::UnboundedSender<(String, RouterOsConnection)>,
}

/// RAII guard for pooled connections
///
/// Ensures connections are always returned to the pool when dropped,
/// preventing memory leaks from forgetting to call `release_connection`.
pub struct PooledConnectionGuard {
    connection: Option<RouterOsConnection>,
    pool: ConnectionPool,
    key: String,
}

impl PooledConnectionGuard {
    /// Get a mutable reference to the underlying connection
    pub(super) fn get_mut(&mut self) -> &mut RouterOsConnection {
        self.connection.as_mut().expect("Connection already taken")
    }
}

impl Drop for PooledConnectionGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            // Send connection back to pool via channel (non-blocking)
            // If send fails, pool is shutting down - connection will be dropped
            if self.pool.return_tx.send((self.key.clone(), conn)).is_err() {
                tracing::trace!(
                    "Failed to return connection (pool shutting down): {}",
                    self.key
                );
            }
        }
    }
}

struct PooledConnection {
    connection: RouterOsConnection,
    last_used: tokio::time::Instant,
}

/// Tracks connection health and error state
#[derive(Clone)]
struct ConnectionState {
    consecutive_errors: u32,
    last_error_time: Option<tokio::time::Instant>,
    last_success_time: Option<tokio::time::Instant>,
}

impl ConnectionState {
    fn new() -> Self {
        Self {
            consecutive_errors: 0,
            last_error_time: None,
            last_success_time: None,
        }
    }

    fn record_success(&mut self) {
        self.consecutive_errors = 0;
        self.last_success_time = Some(tokio::time::Instant::now());
    }

    fn record_error(&mut self) {
        self.consecutive_errors = self.consecutive_errors.saturating_add(1);
        self.last_error_time = Some(tokio::time::Instant::now());
    }

    fn backoff_delay(&self) -> Duration {
        // Exponential backoff: 2^n seconds, max 5 minutes
        let base_delay = 2u64.pow(self.consecutive_errors.min(backoff::MAX_BACKOFF_EXPONENT));
        let max_secs = timeouts::MAX_BACKOFF.as_secs();
        Duration::from_secs(base_delay.min(max_secs))
    }

    fn should_skip_attempt(&self) -> bool {
        // Skip if we've had many consecutive errors and not enough time has passed
        if self.consecutive_errors < backoff::MIN_ERRORS_FOR_BACKOFF {
            return false;
        }

        // After 10 consecutive errors, require 1 hour wait
        if self.consecutive_errors >= backoff::LONG_BACKOFF_ERROR_THRESHOLD {
            if let Some(last_err) = self.last_error_time {
                return last_err.elapsed() < backoff::LONG_BACKOFF_DURATION;
            }
            return true;
        }

        // For moderate errors, use exponential backoff
        if let Some(last_error) = self.last_error_time {
            last_error.elapsed() < self.backoff_delay()
        } else {
            false
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPool {
    pub fn new() -> Self {
        let (return_tx, return_rx) = mpsc::unbounded_channel();
        let connections = Arc::new(Mutex::new(HashMap::new()));
        let connection_states = Arc::new(Mutex::new(HashMap::new()));

        // Try to spawn background task for connection returns
        // Only works if called from within tokio runtime context
        if tokio::runtime::Handle::try_current().is_ok() {
            let connections_clone = connections.clone();
            tokio::spawn(async move {
                let mut rx = return_rx;
                while let Some((key, conn)) = rx.recv().await {
                    let mut pool = connections_clone.lock().await;
                    tracing::trace!("Connection returned to pool via channel: {}", key);
                    pool.insert(
                        key,
                        PooledConnection {
                            connection: conn,
                            last_used: tokio::time::Instant::now(),
                        },
                    );
                }
                tracing::debug!("Connection return channel closed");
            });
        }

        Self {
            connections,
            connection_states,
            max_idle_time: timeouts::POOL_IDLE_TIMEOUT,
            return_tx,
        }
    }

    /// Get or create a connection from the pool with RAII guard
    ///
    /// This method returns a guard that automatically returns the connection
    /// to the pool when dropped, preventing memory leaks.
    ///
    /// This method is internal (pub(super)) to the mikrotik module.
    /// It implements connection pooling with exponential backoff for failed connections.
    pub(super) async fn get_connection(
        &self,
        addr: &str,
        username: &str,
        password: &str,
    ) -> Result<PooledConnectionGuard, Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("{addr}:{username}");

        tracing::trace!("Requesting connection for key: {}", key);

        // Check connection state and apply backoff if needed
        {
            let mut states = self.connection_states.lock().await;
            let state = states
                .entry(key.clone())
                .or_insert_with(ConnectionState::new);

            if state.should_skip_attempt() {
                let delay = state.backoff_delay();
                tracing::debug!(
                    "Skipping connection attempt to {} (backoff: {} consecutive errors, delay: {:?})",
                    addr,
                    state.consecutive_errors,
                    delay
                );
                return Err(format!(
                    "Connection to {} temporarily disabled due to {} consecutive errors",
                    addr, state.consecutive_errors
                )
                .into());
            }
        }

        // Check if we have an available connection
        let conn = {
            let mut pool = self.connections.lock().await;
            if let Some(mut pooled) = pool.remove(&key) {
                if pooled.last_used.elapsed() < self.max_idle_time {
                    tracing::debug!("Reusing connection from pool for {}", addr);
                    tracing::trace!("Connection last used: {:?} ago", pooled.last_used.elapsed());
                    pooled.last_used = tokio::time::Instant::now();
                    Some(pooled.connection)
                } else {
                    tracing::debug!("Connection expired for {}, removing", addr);
                    tracing::trace!(
                        "Connection age: {:?} (max: {:?})",
                        pooled.last_used.elapsed(),
                        self.max_idle_time
                    );
                    // Don't put it back, let it drop
                    None
                }
            } else {
                None
            }
        };

        let conn = if let Some(c) = conn {
            c
        } else {
            // Create new connection
            tracing::debug!("Creating new connection for {}", addr);
            tracing::trace!("Pool key: {}", key);
            match RouterOsConnection::connect(addr).await {
                Ok(mut conn) => {
                    tracing::trace!("Connection established, attempting login");
                    match conn.login(username, password).await {
                        Ok(()) => {
                            tracing::trace!("Login successful, connection ready");
                            // Record success
                            let mut states = self.connection_states.lock().await;
                            if let Some(state) = states.get_mut(&key) {
                                state.record_success();
                                tracing::trace!("Connection state reset after successful login");
                            }
                            conn
                        }
                        Err(e) => {
                            tracing::trace!("Login failed: {}", e);
                            // Record error
                            let mut states = self.connection_states.lock().await;
                            if let Some(state) = states.get_mut(&key) {
                                state.record_error();
                                tracing::trace!(
                                    "Login error recorded, consecutive errors: {}",
                                    state.consecutive_errors
                                );
                            }
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    tracing::trace!("Connection failed: {}", e);
                    // Record connection error
                    let mut states = self.connection_states.lock().await;
                    if let Some(state) = states.get_mut(&key) {
                        state.record_error();
                        tracing::trace!(
                            "Connection error recorded, consecutive errors: {}",
                            state.consecutive_errors
                        );
                    }
                    return Err(e);
                }
            }
        };

        Ok(PooledConnectionGuard {
            connection: Some(conn),
            pool: self.clone(),
            key,
        })
    }

    /// Record successful operation
    pub(super) async fn record_success(&self, addr: &str, username: &str) {
        let key = format!("{addr}:{username}");
        let mut states = self.connection_states.lock().await;
        let state = states.entry(key).or_insert_with(ConnectionState::new);
        state.record_success();
    }

    /// Record failed operation
    pub(super) async fn record_error(&self, addr: &str, username: &str) {
        let key = format!("{addr}:{username}");
        let mut states = self.connection_states.lock().await;
        let state = states.entry(key).or_insert_with(ConnectionState::new);
        state.record_error();
    }

    /// Get connection state for metrics
    pub async fn get_connection_state(&self, addr: &str, username: &str) -> Option<(u32, bool)> {
        let key = format!("{addr}:{username}");
        let states = self.connection_states.lock().await;
        states
            .get(&key)
            .map(|state| (state.consecutive_errors, state.last_success_time.is_some()))
    }

    /// Get pool statistics for metrics
    pub async fn get_pool_stats(&self) -> (usize, usize) {
        let pool = self.connections.lock().await;
        let total = pool.len();
        // All connections in pool are currently idle (not in use)
        // Active connections are those removed from pool temporarily
        let active = 0;
        (total, active)
    }

    /// Clean up expired connections
    pub async fn cleanup(&self) {
        let mut pool = self.connections.lock().await;
        pool.retain(|key, pooled| {
            let should_keep = pooled.last_used.elapsed() < self.max_idle_time;
            if !should_keep {
                tracing::debug!("Cleaning up expired connection: {}", key);
            }
            should_keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_new() {
        let state = ConnectionState::new();
        assert_eq!(state.consecutive_errors, 0);
        assert!(state.last_error_time.is_none());
        assert!(state.last_success_time.is_none());
    }

    #[test]
    fn test_connection_state_record_success() {
        let mut state = ConnectionState::new();
        state.consecutive_errors = 5;

        state.record_success();

        assert_eq!(state.consecutive_errors, 0);
        assert!(state.last_success_time.is_some());
    }

    #[test]
    fn test_connection_state_record_error() {
        let mut state = ConnectionState::new();

        state.record_error();
        assert_eq!(state.consecutive_errors, 1);
        assert!(state.last_error_time.is_some());

        state.record_error();
        assert_eq!(state.consecutive_errors, 2);
    }

    #[test]
    fn test_connection_state_backoff_delay() {
        let mut state = ConnectionState::new();

        // 0 errors -> 2^0 = 1 second
        assert_eq!(state.backoff_delay(), Duration::from_secs(1));

        // After 1 error -> 2^1 = 2 seconds
        state.record_error();
        assert_eq!(state.backoff_delay(), Duration::from_secs(2));

        // After 2 errors -> 2^2 = 4 seconds
        state.record_error();
        assert_eq!(state.backoff_delay(), Duration::from_secs(4));

        // After 3 errors -> 2^3 = 8 seconds
        state.record_error();
        assert_eq!(state.backoff_delay(), Duration::from_secs(8));

        // After 8 errors -> 2^8 = 256 seconds (max power before capping)
        for _ in 0..5 {
            state.record_error();
        }
        assert_eq!(state.consecutive_errors, 8);
        assert_eq!(state.backoff_delay(), Duration::from_secs(256));

        // After 9+ errors -> still 2^8 = 256 due to min(8) in formula
        state.record_error();
        assert_eq!(state.consecutive_errors, 9);
        assert_eq!(state.backoff_delay(), Duration::from_secs(256));

        // Even with many more errors, stays at 256
        for _ in 0..10 {
            state.record_error();
        }
        assert_eq!(state.backoff_delay(), Duration::from_secs(256));
    }

    #[test]
    fn test_connection_state_should_skip_attempt() {
        let mut state = ConnectionState::new();

        // Less than 3 errors -> should not skip
        assert!(!state.should_skip_attempt());

        state.record_error();
        assert!(!state.should_skip_attempt());

        state.record_error();
        assert!(!state.should_skip_attempt());

        // 3 errors -> should skip (backoff)
        state.record_error();
        assert!(state.should_skip_attempt());
    }

    #[test]
    fn test_connection_pool_new() {
        let pool = ConnectionPool::new();
        assert_eq!(pool.max_idle_time, Duration::from_secs(300));
    }

    #[test]
    fn test_connection_pool_default() {
        let pool = ConnectionPool::default();
        assert_eq!(pool.max_idle_time, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_connection_pool_stats_empty() {
        let pool = ConnectionPool::new();
        let (total, active) = pool.get_pool_stats().await;
        assert_eq!(total, 0);
        assert_eq!(active, 0);
    }

    #[tokio::test]
    async fn test_record_success() {
        let pool = ConnectionPool::new();
        pool.record_success("192.168.1.1", "admin").await;

        let states = pool.connection_states.lock().await;
        let key = "192.168.1.1:admin";
        assert!(states.contains_key(key));
        assert_eq!(states[key].consecutive_errors, 0);
    }

    #[tokio::test]
    async fn test_record_error() {
        let pool = ConnectionPool::new();
        pool.record_error("192.168.1.1", "admin").await;

        let states = pool.connection_states.lock().await;
        let key = "192.168.1.1:admin";
        assert!(states.contains_key(key));
        assert_eq!(states[key].consecutive_errors, 1);
    }

    #[tokio::test]
    async fn test_get_connection_state() {
        let pool = ConnectionPool::new();
        pool.record_error("192.168.1.1", "admin").await;
        pool.record_error("192.168.1.1", "admin").await;

        let result = pool.get_connection_state("192.168.1.1", "admin").await;
        assert!(result.is_some());

        let (errors, has_success) = result.unwrap();
        assert_eq!(errors, 2);
        assert!(!has_success);
    }

    #[tokio::test]
    async fn test_cleanup_empty_pool() {
        let pool = ConnectionPool::new();
        pool.cleanup().await;

        let (total, _) = pool.get_pool_stats().await;
        assert_eq!(total, 0);
    }
}
