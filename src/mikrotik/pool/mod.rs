// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Connection pool for managing `RouterOS` connections.
//!
//! # Architecture
//!
//! This module implements a connection pooling mechanism for `RouterOS` API connections
//! to `MikroTik` devices. It provides efficient connection reuse and handles connection
//! failures with exponential backoff.
//!
//! ## Key Components
//!
//! - **`ConnectionPool`**: Thread-safe pool managing multiple connections using `Arc<Mutex<HashMap>>`
//! - **`PooledConnectionGuard`**: RAII guard ensuring connections are always returned to the pool
//! - **`ConnectionState`**: Tracks connection health with error state and backoff behavior
//!
//! ## Connection Lifecycle
//!
//! 1. Acquisition: `get_connection()` retrieves or creates a connection
//!    - Applies backoff when recent failures occurred
//!    - Reuses idle connections when available
//!    - Creates and authenticates new connections on demand
//! 2. Usage: each connection is wrapped in `PooledConnectionGuard`
//!    - Guard provides mutable access via `get_mut()`
//!    - RAII return happens automatically on drop
//! 3. Return: guard drop returns usable connections back to the pool
//!    - Fast path uses a non-blocking `try_lock()`
//!    - Fallback path spawns an async reinsertion task when needed
//!    - Updates active connection counter atomically

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tokio::sync::Mutex;

mod guard;
mod ops;
mod types;

pub(crate) use guard::PooledConnectionGuard;
use types::timeouts;
use types::{ConnectionState, PooledConnection};

/// Connection pool for reusing `RouterOS` connections.
#[derive(Clone)]
pub struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, PooledConnection>>>,
    connection_states: Arc<Mutex<HashMap<String, ConnectionState>>>,
    active_connections: Arc<AtomicUsize>,
    max_idle_time: Duration,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPool {
    #[must_use]
    pub fn new() -> Self {
        let connections = Arc::new(Mutex::new(HashMap::new()));
        let connection_states = Arc::new(Mutex::new(HashMap::new()));
        let active_connections = Arc::new(AtomicUsize::new(0));

        Self {
            connections,
            connection_states,
            active_connections,
            max_idle_time: timeouts::POOL_IDLE_TIMEOUT,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

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

        // 0 errors -> 2^0
        assert_eq!(state.backoff_delay(), Duration::from_secs(1));

        state.record_error();
        assert_eq!(state.backoff_delay(), Duration::from_secs(2));

        state.record_error();
        assert_eq!(state.backoff_delay(), Duration::from_secs(4));

        state.record_error();
        assert_eq!(state.backoff_delay(), Duration::from_secs(8));

        state.record_error();
        assert_eq!(state.backoff_delay(), Duration::from_secs(16));

        state.record_error();
        assert_eq!(state.backoff_delay(), Duration::from_secs(32));

        state.record_error();
        assert_eq!(state.consecutive_errors, 6);
        assert_eq!(state.backoff_delay(), Duration::from_secs(64));

        state.record_error();
        assert_eq!(state.consecutive_errors, 7);
        assert_eq!(state.backoff_delay(), Duration::from_secs(64));

        for _ in 0..10 {
            state.record_error();
        }
        assert_eq!(state.backoff_delay(), Duration::from_secs(64));
    }

    #[test]
    fn test_connection_state_should_skip_attempt() {
        let mut state = ConnectionState::new();

        assert!(!state.should_skip_attempt());

        state.record_error();
        assert!(!state.should_skip_attempt());

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
        pool.record_success("192.168.1.1", "admin", None).await;

        let states = pool.connection_states.lock().await;
        let key = "192.168.1.1:admin";
        assert!(states.contains_key(key));
        assert_eq!(states[key].consecutive_errors, 0);
    }

    #[tokio::test]
    async fn test_record_error() {
        let pool = ConnectionPool::new();
        pool.record_error("192.168.1.1", "admin", None).await;

        let states = pool.connection_states.lock().await;
        let key = "192.168.1.1:admin";
        assert!(states.contains_key(key));
        assert_eq!(states[key].consecutive_errors, 1);
    }

    #[tokio::test]
    async fn test_get_connection_state() {
        let pool = ConnectionPool::new();
        pool.record_error("192.168.1.1", "admin", None).await;
        pool.record_error("192.168.1.1", "admin", None).await;

        let result = pool
            .get_connection_state("192.168.1.1", "admin", None)
            .await;
        assert!(result.is_some());

        let (errors, has_success) = result.expect("state should exist");
        assert_eq!(errors, 2);
        assert!(!has_success);
    }

    #[tokio::test]
    async fn test_get_connection_state_aggregates_groups_when_group_none() {
        let pool = ConnectionPool::new();
        pool.record_error("192.168.1.1", "admin", Some("system"))
            .await;
        pool.record_error("192.168.1.1", "admin", Some("system"))
            .await;
        pool.record_success("192.168.1.1", "admin", Some("firewall"))
            .await;

        let result = pool
            .get_connection_state("192.168.1.1", "admin", None)
            .await;

        assert!(result.is_some());
        let (errors, has_success) = result.expect("aggregated state should exist");
        assert_eq!(errors, 2);
        assert!(has_success);
    }

    #[tokio::test]
    async fn test_cleanup_states_keeps_grouped_keys_for_active_router() {
        let pool = ConnectionPool::new();
        pool.record_error("192.168.1.1:8728", "admin", Some("system"))
            .await;
        pool.record_error("192.168.1.1:8728", "admin", Some("firewall"))
            .await;

        let active = HashSet::from(["192.168.1.1:8728:admin".to_string()]);
        pool.cleanup_states(&active).await;

        let system_state = pool
            .get_connection_state("192.168.1.1:8728", "admin", Some("system"))
            .await;
        let firewall_state = pool
            .get_connection_state("192.168.1.1:8728", "admin", Some("firewall"))
            .await;

        assert!(system_state.is_some());
        assert!(firewall_state.is_some());
    }

    #[tokio::test]
    async fn test_cleanup_empty_pool() {
        let pool = ConnectionPool::new();
        pool.cleanup().await;

        let (total, _) = pool.get_pool_stats().await;
        assert_eq!(total, 0);
    }

    #[tokio::test]
    async fn test_get_connection_records_failure() {
        let pool = ConnectionPool::new();
        let result = pool
            .get_connection("invalid://address", "admin", "", Some("system"))
            .await;

        assert!(result.is_err());
    }
}
