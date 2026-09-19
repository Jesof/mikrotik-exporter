// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Internal methods for `ConnectionPool` operations.

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
        tls: Option<&crate::config::RouterTlsConfig>,
    ) -> Result<PooledConnectionGuard> {
        let key = super::types::ConnectionKey {
            address: addr.into(),
            username: username.into(),
            credential: password.into(),
            group: group.map(str::to_string),
            tls: tls.cloned(),
        };

        {
            let mut states = self.connection_states.lock().await;
            let state = states
                .entry(key.clone())
                .or_insert_with(ConnectionState::new);

            if state.should_skip_attempt() {
                let delay = state.remaining_retry_delay();
                tracing::info!(
                    addr = %addr,
                    consecutive_errors = state.consecutive_errors,
                    retry_delay_secs = ?delay,
                    "Router in backoff mode, skipping connection attempt"
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
                if pooled.last_used.elapsed() < self.max_idle_time
                    && pooled.connection.is_reusable()
                {
                    tracing::debug!(addr = %addr, "Reusing connection from pool");
                    tracing::trace!(idle = ?pooled.last_used.elapsed(), "Connection last used");
                    pooled.last_used = tokio::time::Instant::now();
                    Some(pooled.connection)
                } else {
                    tracing::debug!(addr = %addr, "Reusing expired connection");
                    tracing::trace!(
                        idle = ?pooled.last_used.elapsed(),
                        max_idle = ?self.max_idle_time,
                        "Connection age exceeds maximum"
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
            tracing::debug!(addr = %addr, "Creating new connection");

            match RouterOsConnection::connect(addr, tls).await {
                Ok(mut conn) => {
                    tracing::trace!(addr = %addr, "Connection established, attempting login");
                    match conn.login(username, password).await {
                        Ok(()) => {
                            tracing::trace!(addr = %addr, "Login successful, connection ready");
                            // A successful login does not prove the subsequent group command works.
                            // Reset backoff only when the caller records a successful operation.
                            conn
                        }
                        Err(error) => {
                            tracing::trace!(addr = %addr, %error, "Login failed");
                            let mut states = self.connection_states.lock().await;
                            let state = states
                                .entry(key.clone())
                                .or_insert_with(ConnectionState::new);
                            state.record_error();
                            tracing::trace!(
                                addr = %addr,
                                consecutive_errors = state.consecutive_errors,
                                "Login error recorded"
                            );
                            return Err(error);
                        }
                    }
                }
                Err(error) => {
                    tracing::trace!(addr = %addr, %error, "Connection failed");
                    let mut states = self.connection_states.lock().await;
                    let state = states
                        .entry(key.clone())
                        .or_insert_with(ConnectionState::new);
                    state.record_error();
                    tracing::trace!(
                        addr = %addr,
                        consecutive_errors = state.consecutive_errors,
                        "Connection error recorded"
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

    /// Record a connection-level timeout/failure for a group from outside a guard.
    ///
    /// Used when an outer group deadline fires and the in-flight guarded future
    /// is cancelled before it can report its own result, so the failed attempt
    /// still drives pool backoff for that group.
    pub(in crate::mikrotik) async fn record_connection_error(
        &self,
        addr: &str,
        username: &str,
        password: &str,
        tls: Option<&crate::config::RouterTlsConfig>,
        group: Option<&str>,
    ) {
        let key = super::types::ConnectionKey {
            address: addr.into(),
            username: username.into(),
            credential: password.into(),
            group: group.map(str::to_string),
            tls: tls.cloned(),
        };
        let mut states = self.connection_states.lock().await;
        let state = states.entry(key).or_insert_with(ConnectionState::new);
        state.record_error();
    }

    /// Record successful operation.
    #[cfg(test)]
    pub(in crate::mikrotik) async fn record_success(
        &self,
        addr: &str,
        username: &str,
        group: Option<&str>,
    ) {
        let key = super::types::ConnectionKey {
            address: addr.into(),
            username: username.into(),
            credential: "".into(),
            group: group.map(str::to_string),
            tls: None,
        };
        let mut states = self.connection_states.lock().await;
        let state = states.entry(key).or_insert_with(ConnectionState::new);
        state.record_success();
    }

    /// Record failed operation.
    #[cfg(test)]
    pub(in crate::mikrotik) async fn record_error(
        &self,
        addr: &str,
        username: &str,
        group: Option<&str>,
    ) {
        let key = super::types::ConnectionKey {
            address: addr.into(),
            username: username.into(),
            credential: "".into(),
            group: group.map(str::to_string),
            tls: None,
        };
        let mut states = self.connection_states.lock().await;
        let state = states.entry(key).or_insert_with(ConnectionState::new);
        state.record_error();
    }

    /// Record a failed operation under the full connection identity.
    ///
    /// Test-only helper for exercising health classification with the same
    /// credential/TLS-aware key used by production code.
    #[cfg(test)]
    pub(crate) async fn record_error_for(
        &self,
        addr: &str,
        username: &str,
        password: &str,
        tls: Option<&crate::config::RouterTlsConfig>,
        group: Option<&str>,
    ) {
        let key = super::types::ConnectionKey {
            address: addr.into(),
            username: username.into(),
            credential: password.into(),
            group: group.map(str::to_string),
            tls: tls.cloned(),
        };
        let mut states = self.connection_states.lock().await;
        let state = states.entry(key).or_insert_with(ConnectionState::new);
        state.record_error();
    }

    /// Get connection state for metrics.
    ///
    /// Matches the full connection identity (address, username, password, TLS
    /// settings) so entries for a different credential or TLS profile, or for
    /// another router sharing an address and username, are not aggregated.
    pub(crate) async fn get_connection_state(
        &self,
        addr: &str,
        username: &str,
        password: &str,
        tls: Option<&crate::config::RouterTlsConfig>,
        group: Option<&str>,
    ) -> Option<(u32, bool)> {
        let states = self.connection_states.lock().await;

        let mut max_errors: u32 = 0;
        let mut has_success = false;
        let mut found = false;

        for (key, state) in states.iter() {
            if key.address == addr
                && key.username == username
                && key.credential.matches(password)
                && key.tls.as_ref() == tls
                && group.is_none_or(|group| key.group.as_deref() == Some(group))
            {
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
    pub(crate) async fn get_pool_stats(&self) -> (usize, usize) {
        let pool = self.connections.lock().await;
        let total = pool.len();
        // All connections in pool are currently idle (not in use)
        // Active connections are those removed from pool temporarily.
        let active = self.active_connections.load(Ordering::Acquire);
        (total, active)
    }

    /// Clean up expired connections.
    pub(crate) async fn cleanup(&self) {
        let mut pool = self.connections.lock().await;
        pool.retain(|key, pooled| {
            let should_keep = pooled.last_used.elapsed() < self.max_idle_time;
            if !should_keep {
                tracing::debug!(key = %key, "Cleaning up expired connection");
            }
            should_keep
        });
    }

    /// Clean up connection state for routers no longer configured.
    ///
    /// Retains states that match the full connection identity of a configured
    /// router (address, username, password, and TLS settings) with any group,
    /// so a router whose credential or TLS profile changed is not kept alive
    /// merely because its address and username are unchanged.
    pub(crate) async fn cleanup_states(&self, active_routers: &[crate::config::RouterConfig]) {
        let mut states = self.connection_states.lock().await;
        let before_count = states.len();
        states.retain(|key, _| {
            active_routers.iter().any(|router| {
                use secrecy::ExposeSecret;
                key.matches_identity(
                    &router.address,
                    &router.username,
                    router.password.expose_secret(),
                    router.tls.as_ref(),
                )
            })
        });
        let removed = before_count - states.len();
        if removed > 0 {
            tracing::debug!(removed, "Removed stale connection state entries");
        }
    }
}
