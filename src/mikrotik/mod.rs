//! `MikroTik` `RouterOS` API client module
//!
//! This module provides functionality to connect to `MikroTik` routers via the `RouterOS` API,
//! authenticate, and collect system and interface metrics.

use crate::config::RouterConfig;
use md5::compute as md5_compute;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

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

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            connection_states: Arc::new(Mutex::new(HashMap::new())),
            max_idle_time: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Get or create a connection from the pool
    async fn get_connection(
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
    async fn record_success(&self, addr: &str, username: &str) {
        let key = format!("{addr}:{username}");
        let mut states = self.connection_states.lock().await;
        if let Some(state) = states.get_mut(&key) {
            state.record_success();
        }
    }

    /// Record failed operation
    async fn record_error(&self, addr: &str, username: &str) {
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
    async fn release_connection(&self, addr: &str, username: &str, conn: RouterOsConnection) {
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

/// Statistics for a network interface
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub running: bool,
}

/// System resource information from a `MikroTik` router
#[derive(Debug, Clone)]
pub struct SystemResource {
    pub uptime: String,
    pub cpu_load: u64,
    pub free_memory: u64,
    pub total_memory: u64,
    pub version: String,
    pub board_name: String,
}

/// Complete metrics snapshot from a router
#[derive(Debug, Clone)]
pub struct RouterMetrics {
    pub router_name: String,
    pub interfaces: Vec<InterfaceStats>,
    pub system: SystemResource,
}

/// `MikroTik` `RouterOS` API client
///
/// Provides methods to connect to `MikroTik` routers via `RouterOS` API
/// and collect system and interface metrics.
pub struct MikroTikClient {
    config: RouterConfig,
    pool: Arc<ConnectionPool>,
}

impl MikroTikClient {
    /// Creates a new `MikroTik` client with a shared connection pool
    #[must_use]
    pub fn with_pool(config: RouterConfig, pool: Arc<ConnectionPool>) -> Self {
        Self { config, pool }
    }

    /// Collects metrics from the router
    ///
    /// This method connects to the router, authenticates, and retrieves
    /// system and interface statistics. Returns placeholder data on error.
    ///
    /// # Errors
    ///
    /// Returns an error if connection or authentication fails.
    pub async fn collect_metrics(
        &self,
    ) -> Result<RouterMetrics, Box<dyn std::error::Error + Send + Sync>> {
        match self.collect_real().await {
            Ok(m) => Ok(m),
            Err(e) => {
                tracing::error!("Router '{}' collection failed: {}", self.config.name, e);
                Ok(RouterMetrics {
                    router_name: self.config.name.clone(),
                    interfaces: Vec::new(),
                    system: SystemResource {
                        uptime: "0s".to_string(),
                        cpu_load: 0,
                        free_memory: 0,
                        total_memory: 0,
                        version: "unknown".to_string(),
                        board_name: "unknown".to_string(),
                    },
                })
            }
        }
    }

    async fn collect_real(
        &self,
    ) -> Result<RouterMetrics, Box<dyn std::error::Error + Send + Sync>> {
        // Get connection from pool
        let mut conn = self
            .pool
            .get_connection(
                &self.config.address,
                &self.config.username,
                &self.config.password,
            )
            .await?;

        let system_result = conn.command("/system/resource/print", &[]).await;
        let interfaces_result = conn.command("/interface/print", &[]).await;

        // Check if operations succeeded and record state
        let success = system_result.is_ok() && interfaces_result.is_ok();
        if success {
            self.pool
                .record_success(&self.config.address, &self.config.username)
                .await;
        } else {
            self.pool
                .record_error(&self.config.address, &self.config.username)
                .await;
        }

        // Always return connection to pool
        self.pool
            .release_connection(&self.config.address, &self.config.username, conn)
            .await;

        let system_sentences = system_result?;
        let interfaces_sentences = interfaces_result?;

        let system = parse_system(&system_sentences);
        let interfaces = parse_interfaces(&interfaces_sentences);

        Ok(RouterMetrics {
            router_name: self.config.name.clone(),
            interfaces,
            system,
        })
    }
}

// ----------------- Low level RouterOS API -----------------

struct RouterOsConnection {
    stream: TcpStream,
}

impl RouterOsConnection {
    async fn connect(addr: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let stream = timeout(Duration::from_secs(5), TcpStream::connect(addr)).await??;
        Ok(Self { stream })
    }

    async fn login(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Try new login method first (RouterOS 6.43+)
        let login_result = self
            .raw_command(vec![
                "/login".to_string(),
                format!("=name={}", username),
                format!("=password={}", password),
            ])
            .await;

        match login_result {
            Ok(sentences) => {
                // Check for error messages
                for s in &sentences {
                    if s.contains_key("message") {
                        let msg = s.get("message").unwrap();
                        if msg.contains("failure") || msg.contains("invalid") {
                            return Err(format!("Login failed: {msg}").into());
                        }
                        tracing::debug!("Login message: {}", msg);
                    }
                }
                tracing::debug!("Login successful (new method)");
                return Ok(());
            }
            Err(e) => {
                tracing::debug!("New login method failed, trying legacy method: {}", e);
            }
        }

        // Fallback to legacy challenge-response method (pre-6.43)
        let sentences = self.raw_command(vec!["/login".to_string()]).await?;
        let mut challenge_hex = None;
        for s in sentences {
            if let Some(ret) = s.get("ret") {
                challenge_hex = Some(ret.clone());
            }
        }
        let challenge_hex = challenge_hex.ok_or("No challenge 'ret' received")?;
        let challenge = hex::decode(&challenge_hex)?;

        // Build MD5 hash of 0 + password + challenge
        let mut data = Vec::with_capacity(1 + password.len() + challenge.len());
        data.push(0u8);
        data.extend_from_slice(password.as_bytes());
        data.extend_from_slice(&challenge);
        let digest = md5_compute(&data);
        let mut response = String::from("00");
        response.push_str(&hex::encode(digest.0));

        let login_sentences = self
            .raw_command(vec![
                "/login".to_string(),
                format!("=name={}", username),
                format!("=response={}", response),
            ])
            .await?;
        // If no !trap assume success
        for s in &login_sentences {
            if s.contains_key("message") {
                tracing::warn!("Login message: {:?}", s.get("message"));
            }
        }
        tracing::debug!("Login successful (legacy method)");
        Ok(())
    }

    async fn command(
        &mut self,
        path: &str,
        args: &[&str],
    ) -> Result<Vec<HashMap<String, String>>, Box<dyn std::error::Error + Send + Sync>> {
        let mut words: Vec<String> = Vec::with_capacity(1 + args.len());
        words.push(path.to_string());
        for a in args {
            words.push((*a).to_string());
        }
        self.raw_command(words).await
    }

    async fn raw_command(
        &mut self,
        words: Vec<String>,
    ) -> Result<Vec<HashMap<String, String>>, Box<dyn std::error::Error + Send + Sync>> {
        self.send_words(&words).await?;
        self.read_sentences().await
    }

    async fn send_words(
        &mut self,
        words: &[String],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for w in words {
            self.write_word(w).await?;
        }
        // zero length word terminator
        self.stream.write_all(&[0]).await?;
        Ok(())
    }

    async fn write_word(
        &mut self,
        word: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bytes = word.as_bytes();
        self.stream.write_all(&encode_length(bytes.len())).await?;
        self.stream.write_all(bytes).await?;
        Ok(())
    }

    async fn read_sentences(
        &mut self,
    ) -> Result<Vec<HashMap<String, String>>, Box<dyn std::error::Error + Send + Sync>> {
        let mut sentences: Vec<HashMap<String, String>> = Vec::new();
        let mut current: Option<HashMap<String, String>> = None;
        loop {
            let word = self.read_word().await?;
            if word.is_empty() {
                continue;
            }
            if word == "!done" {
                if let Some(s) = current.take() {
                    sentences.push(s);
                }
                break;
            }
            if word == "!trap" {
                // collect trap details
                let mut trap = HashMap::new();
                loop {
                    let w = self.read_word().await?;
                    if w.is_empty() {
                        continue;
                    }
                    if let Some(stripped) = w.strip_prefix('=') {
                        if let Some((k, v)) = stripped.split_once('=') {
                            trap.insert(k.to_string(), v.to_string());
                        }
                        continue;
                    }
                    if w.starts_with('!') || w == "!done" {
                        break;
                    }
                }
                let msg = trap
                    .get("message")
                    .cloned()
                    .unwrap_or_else(|| "trap".to_string());
                return Err(format!("RouterOS trap: {msg}").into());
            }
            if word == "!re" {
                if let Some(s) = current.take() {
                    sentences.push(s);
                }
                current = Some(HashMap::new());
                continue;
            }
            if let Some(stripped) = word.strip_prefix('=') {
                let tgt = current.get_or_insert(HashMap::new());
                if let Some((k, v)) = stripped.split_once('=') {
                    tgt.insert(k.to_string(), v.to_string());
                }
            }
            // ignore other headers
        }
        Ok(sentences)
    }

    async fn read_word(&mut self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let len = self.read_length().await?;
        if len == 0 {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(String::from_utf8_lossy(&buf).into())
    }

    async fn read_length(&mut self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let first = self.stream.read_u8().await?;
        let len = if first & 0x80 == 0 {
            first as usize
        } else if first & 0xC0 == 0x80 {
            let second = self.stream.read_u8().await?;
            (((first & 0x3F) as usize) << 8) + second as usize
        } else if first & 0xE0 == 0xC0 {
            let second = self.stream.read_u8().await?;
            let third = self.stream.read_u8().await?;
            (((first & 0x1F) as usize) << 16) + ((second as usize) << 8) + third as usize
        } else if first & 0xF0 == 0xE0 {
            let second = self.stream.read_u8().await?;
            let third = self.stream.read_u8().await?;
            let fourth = self.stream.read_u8().await?;
            (((first & 0x0F) as usize) << 24)
                + ((second as usize) << 16)
                + ((third as usize) << 8)
                + fourth as usize
        } else {
            // five byte length
            let b2 = self.stream.read_u8().await?;
            let b3 = self.stream.read_u8().await?;
            let b4 = self.stream.read_u8().await?;
            let b5 = self.stream.read_u8().await?;
            ((first & 0x07) as usize) << 32
                | (b2 as usize) << 24
                | (b3 as usize) << 16
                | (b4 as usize) << 8
                | b5 as usize
        };
        Ok(len)
    }
}

// RouterOS protocol length encoding - intentional truncation is part of the wire format
#[allow(clippy::cast_possible_truncation)]
fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x4000 {
        vec![((len >> 8) as u8) | 0x80, (len & 0xFF) as u8]
    } else if len < 0x0020_0000 {
        vec![
            ((len >> 16) as u8) | 0xC0,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    } else if len < 0x1000_0000 {
        vec![
            ((len >> 24) as u8) | 0xE0,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    } else {
        vec![
            ((len >> 32) as u8) | 0xF0,
            ((len >> 24) & 0xFF) as u8,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

fn parse_system(sentences: &[HashMap<String, String>]) -> SystemResource {
    let first_opt = sentences.iter().find(|s| s.contains_key("version"));
    let empty = HashMap::new();
    let first = first_opt.unwrap_or(&empty);
    SystemResource {
        uptime: first
            .get("uptime")
            .cloned()
            .unwrap_or_else(|| "0s".to_string()),
        cpu_load: first
            .get("cpu-load")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        free_memory: first
            .get("free-memory")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        total_memory: first
            .get("total-memory")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        version: first
            .get("version")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        board_name: first
            .get("board-name")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
    }
}

fn parse_interfaces(sentences: &[HashMap<String, String>]) -> Vec<InterfaceStats> {
    let mut out = Vec::new();
    for s in sentences {
        if let Some(name) = s.get("name") {
            out.push(InterfaceStats {
                name: name.clone(),
                rx_bytes: s.get("rx-byte").and_then(|v| v.parse().ok()).unwrap_or(0),
                tx_bytes: s.get("tx-byte").and_then(|v| v.parse().ok()).unwrap_or(0),
                rx_packets: s.get("rx-packet").and_then(|v| v.parse().ok()).unwrap_or(0),
                tx_packets: s.get("tx-packet").and_then(|v| v.parse().ok()).unwrap_or(0),
                rx_errors: s.get("rx-error").and_then(|v| v.parse().ok()).unwrap_or(0),
                tx_errors: s.get("tx-error").and_then(|v| v.parse().ok()).unwrap_or(0),
                running: s.get("running").is_some_and(|v| v == "true"),
            });
        }
    }
    out
}
