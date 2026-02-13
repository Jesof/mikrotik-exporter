// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Low-level RouterOS API connection handling

mod auth;
mod parse;
mod protocol;

use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub(crate) use parse::{parse_connection_tracking, parse_interfaces, parse_system};
pub use protocol::encode_length;
use protocol::read_length;

/// Connection timeout (5 seconds)
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Read operation timeout (30 seconds)
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Low-level RouterOS API connection
pub(super) struct RouterOsConnection {
    stream: TcpStream,
}

impl RouterOsConnection {
    pub(super) async fn connect(
        addr: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        tracing::trace!("Attempting TCP connection to: {}", addr);
        let stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await??;
        tracing::trace!("TCP connection established to: {}", addr);
        Ok(Self { stream })
    }

    pub(super) async fn command(
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
        // Wrap the entire read operation in a timeout to prevent hanging on slow/dead connections
        timeout(READ_TIMEOUT, async {
            let mut sentences: Vec<HashMap<String, String>> = Vec::new();
            let mut current: Option<HashMap<String, String>> = None;
            loop {
                let word = self.read_word().await?;
                if word.is_empty() {
                    continue;
                }
                tracing::trace!("Received word: {}", word);
                if word == "!done" {
                    if let Some(s) = current.take() {
                        sentences.push(s);
                    }
                    tracing::trace!("Command complete, {} sentences received", sentences.len());
                    break;
                }
                if word == "!trap" {
                    tracing::trace!("Trap received, reading trap details");
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
        })
        .await
        .map_err(|_| "Read timeout: RouterOS did not respond within 30 seconds")?
    }

    async fn read_word(&mut self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let len = read_length(&mut self.stream).await?;
        if len == 0 {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(String::from_utf8_lossy(&buf).into())
    }
}
