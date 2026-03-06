// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Low-level `RouterOS` API connection handling

use crate::prelude::{AppError, Result};
mod auth;
mod protocol;

use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub use protocol::encode_length;
use protocol::read_length;

/// Connection timeout (5 seconds)
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Read operation timeout (30 seconds)
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Low-level `RouterOS` API connection
pub(super) struct RouterOsConnection {
    stream: TcpStream,
}

impl RouterOsConnection {
    pub(super) async fn connect(addr: &str) -> Result<Self> {
        tracing::trace!("Attempting TCP connection to: {}", addr);
        let stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                AppError::RouterOs(format!(
                    "TCP connection timeout to {addr} after {}s",
                    CONNECTION_TIMEOUT.as_secs()
                ))
            })??;
        tracing::trace!("TCP connection established to: {}", addr);
        Ok(Self { stream })
    }

    pub(super) async fn command(
        &mut self,
        path: &str,
        args: &[&str],
    ) -> Result<Vec<HashMap<String, String>>> {
        let mut words: Vec<String> = Vec::with_capacity(1 + args.len());
        words.push(path.to_string());
        for a in args {
            words.push((*a).to_string());
        }
        self.raw_command(words)
            .await
            .map_err(|error| with_command_context(path, "command execution", &error))
    }

    async fn raw_command(&mut self, words: Vec<String>) -> Result<Vec<HashMap<String, String>>> {
        let command = words.first().map_or("<unknown>", String::as_str);
        self.send_words(&words)
            .await
            .map_err(|error| with_command_context(command, "request send", &error))?;
        self.read_sentences()
            .await
            .map_err(|error| with_command_context(command, "response read", &error))
    }

    async fn send_words(&mut self, words: &[String]) -> Result<()> {
        for (index, word) in words.iter().enumerate() {
            self.write_word(word).await.map_err(|error| {
                AppError::RouterOs(format!(
                    "Failed to write command word #{index} ({}): {}",
                    redact_routeros_word(word),
                    app_error_message(&error)
                ))
            })?;
        }
        // zero length word terminator
        self.stream.write_all(&[0]).await.map_err(|error| {
            AppError::RouterOs(format!("Failed to write command terminator: {error}"))
        })?;
        Ok(())
    }

    async fn write_word(&mut self, word: &str) -> Result<()> {
        let bytes = word.as_bytes();
        self.stream
            .write_all(&encode_length(bytes.len()))
            .await
            .map_err(|error| {
                AppError::RouterOs(format!(
                    "Failed to write word length for {}: {error}",
                    redact_routeros_word(word)
                ))
            })?;
        self.stream.write_all(bytes).await.map_err(|error| {
            AppError::RouterOs(format!(
                "Failed to write word bytes for {}: {error}",
                redact_routeros_word(word)
            ))
        })?;
        Ok(())
    }

    async fn read_sentences(&mut self) -> Result<Vec<HashMap<String, String>>> {
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
                    return Err(AppError::RouterOs(format!("RouterOS trap: {msg}")));
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
        .map_err(|_| {
            AppError::RouterOs(format!(
                "Read timeout: RouterOS did not respond within {} seconds",
                READ_TIMEOUT.as_secs()
            ))
        })?
    }

    async fn read_word(&mut self) -> Result<String> {
        let len = read_length(&mut self.stream).await.map_err(|error| {
            AppError::RouterOs(format!(
                "Failed to decode RouterOS word length: {}",
                app_error_message(&error)
            ))
        })?;
        if len == 0 {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await.map_err(|error| {
            AppError::RouterOs(format!(
                "Failed to read RouterOS word body ({len} bytes): {error}"
            ))
        })?;
        Ok(String::from_utf8_lossy(&buf).into())
    }
}

fn with_command_context(command: &str, phase: &str, error: &AppError) -> AppError {
    AppError::RouterOs(format!(
        "Command '{}' failed during {}: {}",
        command,
        phase,
        app_error_message(error)
    ))
}

fn app_error_message(error: &AppError) -> String {
    match error {
        AppError::Config(message) | AppError::RouterOs(message) | AppError::Metrics(message) => {
            message.clone()
        }
        AppError::Io(io_error) => io_error.to_string(),
        AppError::AddrParse(parse_error) => parse_error.to_string(),
    }
}

fn redact_routeros_word(word: &str) -> String {
    if word.starts_with("=password=") {
        return "=password=<redacted>".to_string();
    }
    if word.starts_with("=response=") {
        return "=response=<redacted>".to_string();
    }
    word.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_routeros_word_redacts_secrets() {
        assert_eq!(
            redact_routeros_word("=password=supersecret"),
            "=password=<redacted>"
        );
        assert_eq!(
            redact_routeros_word("=response=abcd1234"),
            "=response=<redacted>"
        );
        assert_eq!(redact_routeros_word("=name=admin"), "=name=admin");
    }

    #[test]
    fn test_with_command_context_contains_command_and_phase() {
        let error = AppError::RouterOs("timeout".to_string());
        let contextual = with_command_context("/system/resource/print", "response read", &error);

        match contextual {
            AppError::RouterOs(message) => {
                assert!(message.contains("/system/resource/print"));
                assert!(message.contains("response read"));
                assert!(message.contains("timeout"));
            }
            _ => panic!("expected RouterOs error"),
        }
    }
}
