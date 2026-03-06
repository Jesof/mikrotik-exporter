// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Internal methods for `ConnectionPool` operations.

use std::collections::HashSet;

use std::sync::atomic::Ordering;

use crate::mikrotik::connection::RouterOsConnection;
use crate::prelude::{AppError, Result};

use super::types::ConnectionState;
use super::{ConnectionPool, PooledConnectionGuard};

impl ConnectionPool {
    /// Get or create a connection from the pool with RAII guard.
    pub(in crate::mikrotik) async fn get_connection(
        &self,
        addr: &str,
        username: &str,
        password: &str,
        group: Option<&str>,
    ) -> Result<PooledConnectionGuard> {
        let key = match group {
            Some(g) => format!("{addr}:{username}:{g}"),
            None => format!("{addr}:{username}"),
        };

        tracing::trace!("Requesting connection for key: {}", key);

        {
            let mut states = self.connection_states.lock().await;
            let state = states
                .entry(key.clone())
                .or_insert_with(ConnectionState::new);

            if state.should_skip_attempt() {
                let delay = state.remaining_retry_delay();
                tracing::info!(
                    "Router {} in backoff mode ({} consecutive errors, next retry in {:?})",
                    addr,
                    state.consecutive_errors,
                    delay
                );
                return Err(AppError::RouterOs(format!(
                    "Connection to {} temporarily disabled due to {} consecutive errors. Will retry in {:?}",
                    addr, state.consecutive_errors, delay
                )));
            }
        }

        let conn = {
            let mut pool = self.connections.lock().await;
            if let Some(mut pooled) = pool.remove(&key) {
                if pooled.last_used.elapsed() < self.max_idle_time {
                    tracing::debug!("Reusing connection from pool for {}", addr);
                    tracing::trace!("Connection last used: {:?} ago", pooled.last_used.elapsed());
                    pooled.last_used = tokio::time::Instant::now();
                    Some(pooled.connection)
                } else {
                    tracing::debug!("Reusing expired connection for {}", addr);
                    tracing::trace!(
                        "Connection age: {:?} (max: {:?})",
                        pooled.last_used.elapsed(),
                        self.max_idle_time
                    );
                    None
                }
            } else {
                None
            }
        };

        let conn = if let Some(c) = conn {
            c
        } else {
            tracing::debug!("Creating new connection for {}", addr);
            tracing::trace!("Pool key: {}", key);

            match RouterOsConnection::connect(addr).await {
                Ok(mut conn) => {
                    tracing::trace!("Connection established, attempting login");
                    match conn.login(username, password).await {
                        Ok(()) => {
                            tracing::trace!("Login successful, connection ready");
                            let mut states = self.connection_states.lock().await;
                            let state = states
                                .entry(key.clone())
                                .or_insert_with(ConnectionState::new);
                            state.record_success();
                            tracing::trace!("Connection state reset after successful login");
                            conn
                        }
                        Err(error) => {
                            tracing::trace!("Login failed: {error}");
                            let mut states = self.connection_states.lock().await;
                            let state = states
                                .entry(key.clone())
                                .or_insert_with(ConnectionState::new);
                            state.record_error();
                            tracing::trace!(
                                "Login error recorded, consecutive errors: {}",
                                state.consecutive_errors
                            );
                            return Err(error);
                        }
                    }
                }
                Err(error) => {
                    tracing::trace!("Connection failed: {error}");
                    let mut states = self.connection_states.lock().await;
                    let state = states
                        .entry(key.clone())
                        .or_insert_with(ConnectionState::new);
                    state.record_error();
                    tracing::trace!(
                        "Connection error recorded, consecutive errors: {}",
                        state.consecutive_errors
                    );
                    return Err(error);
                }
            }
        };

        self.active_connections
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        Ok(PooledConnectionGuard {
            connection: Some(conn),
            pool: self.clone(),
            key,
            broken: false,
        })
    }

    /// Record successful operation.
    pub(in crate::mikrotik) async fn record_success(
        &self,
        addr: &str,
        username: &str,
        group: Option<&str>,
    ) {
        let key = match group {
            Some(g) => format!("{addr}:{username}:{g}"),
            None => format!("{addr}:{username}"),
        };
        let mut states = self.connection_states.lock().await;
        let state = states.entry(key).or_insert_with(ConnectionState::new);
        state.record_success();
    }

    /// Record failed operation.
    pub(in crate::mikrotik) async fn record_error(
        &self,
        addr: &str,
        username: &str,
        group: Option<&str>,
    ) {
        let key = match group {
            Some(g) => format!("{addr}:{username}:{g}"),
            None => format!("{addr}:{username}"),
        };
        let mut states = self.connection_states.lock().await;
        let state = states.entry(key).or_insert_with(ConnectionState::new);
        state.record_error();
    }

    /// Get connection state for metrics.
    pub(crate) async fn get_connection_state(
        &self,
        addr: &str,
        username: &str,
        group: Option<&str>,
    ) -> Option<(u32, bool)> {
        let states = self.connection_states.lock().await;

        if let Some(g) = group {
            let key = format!("{addr}:{username}:{g}");
            return states
                .get(&key)
                .map(|state| (state.consecutive_errors, state.last_success_time.is_some()));
        }

        let base_key = format!("{addr}:{username}");
        let grouped_prefix = format!("{base_key}:");
        let mut max_errors: u32 = 0;
        let mut has_success = false;
        let mut found = false;

        for (key, state) in states.iter() {
            if key == &base_key || key.starts_with(&grouped_prefix) {
                found = true;
                max_errors = max_errors.max(state.consecutive_errors);
                has_success |= state.last_success_time.is_some();
            }
        }

        if found {
            Some((max_errors, has_success))
        } else {
            None
        }
    }

    /// Get pool statistics for metrics.
    pub async fn get_pool_stats(&self) -> (usize, usize) {
        let pool = self.connections.lock().await;
        let total = pool.len();
        // All connections in pool are currently idle (not in use)
        // Active connections are those removed from pool temporarily.
        let active = self.active_connections.load(Ordering::Acquire);
        (total, active)
    }

    /// Clean up expired connections.
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

    /// Clean up connection state for routers no longer configured.
    pub async fn cleanup_states(&self, active_keys: &HashSet<String>) {
        let mut states = self.connection_states.lock().await;
        let before_count = states.len();
        states.retain(|key, _| {
            active_keys
                .iter()
                .any(|base_key| key == base_key || key.starts_with(&format!("{base_key}:")))
        });
        let removed = before_count - states.len();
        if removed > 0 {
            tracing::debug!("Removed {} stale connection state entries", removed);
        }
    }
}
