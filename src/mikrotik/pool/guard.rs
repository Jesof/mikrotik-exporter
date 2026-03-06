// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Connection guard that returns pooled connections on drop.

use std::sync::atomic::Ordering;

use crate::mikrotik::connection::RouterOsConnection;

use super::ConnectionPool;

/// RAII guard for pooled connections.
///
/// Ensures connections are always returned to the pool when dropped.
pub(crate) struct PooledConnectionGuard {
    pub(super) connection: Option<RouterOsConnection>,
    pub(super) pool: ConnectionPool,
    pub(super) key: String,
    pub(super) broken: bool,
}

impl PooledConnectionGuard {
    /// Get a mutable reference to the underlying connection.
    pub(in crate::mikrotik) fn get_mut(&mut self) -> &mut RouterOsConnection {
        self.connection.as_mut().expect("Connection already taken")
    }

    /// Mark current connection as broken so it won't be returned to pool.
    pub(in crate::mikrotik) fn mark_broken(&mut self) {
        self.broken = true;
    }
}

impl Drop for PooledConnectionGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            if self.broken {
                tracing::debug!("Dropping broken connection: {}", self.key);
            } else if let Err(error) = self.pool.return_tx.send((self.key.clone(), conn)) {
                tracing::debug!(
                    "Failed to return connection (pool shutting down): {} ({error})",
                    self.key
                );
            }
        }

        // Saturating decrement via CAS loop to prevent underflow race.
        let active = &self.pool.active_connections;
        loop {
            let current = active.load(Ordering::Acquire);
            if current == 0 {
                tracing::warn!(
                    "Active connection count underflow detected for key: {}",
                    self.key
                );
                break;
            }

            if active
                .compare_exchange_weak(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
    }
}
