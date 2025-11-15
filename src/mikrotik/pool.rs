//! Connection pool for managing RouterOS connections

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use super::connection::RouterOsConnection;

/// Connection pool for reusing `RouterOS` connections
pub struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, PooledConnection>>>,
    connection_states: Arc<Mutex<HashMap<String, ConnectionState>>>,
    max_idle_time: Duration,
}

struct PooledConnection {
    connection: RouterOsConnection,
    last_used: tokio::time::Instant,
    in_use: bool,
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
        let base_delay = 2u64.pow(self.consecutive_errors.min(8));
        Duration::from_secs(base_delay.min(300))
    }

    fn should_skip_attempt(&self) -> bool {
        // Skip if we've had many consecutive errors and not enough time has passed
        if self.consecutive_errors < 3 {
            return false;
        }

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
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            connection_states: Arc::new(Mutex::new(HashMap::new())),
            max_idle_time: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Get or create a connection from the pool
    pub(super) async fn get_connection(
        &self,
        addr: &str,
        username: &str,
        password: &str,
    ) -> Result<RouterOsConnection, Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("{addr}:{username}");

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
        {
            let mut pool = self.connections.lock().await;
            if let Some(pooled) = pool.get_mut(&key) {
                if !pooled.in_use && pooled.last_used.elapsed() < self.max_idle_time {
                    tracing::debug!("Reusing connection from pool for {}", addr);
                    pooled.in_use = true;
                    pooled.last_used = tokio::time::Instant::now();

                    // Move connection out of pool temporarily
                    let conn = pool.remove(&key).unwrap().connection;
                    return Ok(conn);
                } else if pooled.last_used.elapsed() >= self.max_idle_time {
                    tracing::debug!("Connection expired for {}, removing", addr);
                    pool.remove(&key);
                }
            }
        }

        // Create new connection
        tracing::debug!("Creating new connection for {}", addr);
        match RouterOsConnection::connect(addr).await {
            Ok(mut conn) => {
                match conn.login(username, password).await {
                    Ok(()) => {
                        // Record success
                        let mut states = self.connection_states.lock().await;
                        if let Some(state) = states.get_mut(&key) {
                            state.record_success();
                        }
                        Ok(conn)
                    }
                    Err(e) => {
                        // Record error
                        let mut states = self.connection_states.lock().await;
                        if let Some(state) = states.get_mut(&key) {
                            state.record_error();
                        }
                        Err(e)
                    }
                }
            }
            Err(e) => {
                // Record connection error
                let mut states = self.connection_states.lock().await;
                if let Some(state) = states.get_mut(&key) {
                    state.record_error();
                }
                Err(e)
            }
        }
    }

    /// Record successful operation
    pub(super) async fn record_success(&self, addr: &str, username: &str) {
        let key = format!("{addr}:{username}");
        let mut states = self.connection_states.lock().await;
        if let Some(state) = states.get_mut(&key) {
            state.record_success();
        }
    }

    /// Record failed operation
    pub(super) async fn record_error(&self, addr: &str, username: &str) {
        let key = format!("{addr}:{username}");
        let mut states = self.connection_states.lock().await;
        if let Some(state) = states.get_mut(&key) {
            state.record_error();
        }
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
        let active = pool.values().filter(|conn| conn.in_use).count();
        (total, active)
    }

    /// Release a connection back to the pool
    pub(super) async fn release_connection(
        &self,
        addr: &str,
        username: &str,
        conn: RouterOsConnection,
    ) {
        let key = format!("{addr}:{username}");
        let mut pool = self.connections.lock().await;

        tracing::debug!("Returning connection to pool for {}", addr);
        pool.insert(
            key,
            PooledConnection {
                connection: conn,
                last_used: tokio::time::Instant::now(),
                in_use: false,
            },
        );
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
