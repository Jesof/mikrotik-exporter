// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! `RouterOS` authentication

use crate::prelude::{AppError, Result};
use md5::compute as md5_compute;

use super::RouterOsConnection;

fn is_auth_failure_message(message: &str) -> bool {
    let lowercase = message.to_ascii_lowercase();
    lowercase.contains("failure") || lowercase.contains("invalid")
}

fn extract_challenge(sentences: &[std::collections::HashMap<String, String>]) -> Option<String> {
    sentences
        .iter()
        .find_map(|sentence| sentence.get("ret").cloned())
}

fn build_legacy_response(password: &str, challenge_hex: &str) -> Result<String> {
    let challenge = hex::decode(challenge_hex).map_err(|error| {
        AppError::RouterOs(format!(
            "Invalid RouterOS challenge hex '{challenge_hex}': {error}"
        ))
    })?;

    let mut data = Vec::with_capacity(1 + password.len() + challenge.len());
    data.push(0u8);
    data.extend_from_slice(password.as_bytes());
    data.extend_from_slice(&challenge);
    let digest = md5_compute(&data);
    let mut response = String::from("00");
    response.push_str(&hex::encode(digest.0));
    Ok(response)
}

impl RouterOsConnection {
    pub(crate) async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        tracing::trace!("Attempting login for user: {}", username);
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
                tracing::trace!(
                    "New login method response received, {} sentences",
                    sentences.len()
                );
                for sentence in &sentences {
                    if let Some(msg) = sentence.get("message") {
                        if is_auth_failure_message(msg) {
                            tracing::trace!("Login failed with message: {}", msg);
                            return Err(AppError::RouterOs(format!(
                                "Login failed (new auth method): {msg}"
                            )));
                        }
                        tracing::debug!("Login message: {}", msg);
                    }
                }
                tracing::debug!("Login successful (new method)");
                return Ok(());
            }
            Err(error) => {
                tracing::debug!("New login method failed, trying legacy method: {}", error);
            }
        }

        tracing::trace!("Requesting challenge for legacy login");
        let challenge_sentences =
            self.raw_command(vec!["/login".to_string()])
                .await
                .map_err(|error| {
                    AppError::RouterOs(format!("Legacy login challenge request failed: {error}"))
                })?;

        let challenge_hex = extract_challenge(&challenge_sentences).ok_or_else(|| {
            AppError::RouterOs("Legacy login failed: no challenge 'ret' received".to_string())
        })?;
        tracing::trace!("Challenge received, length: {}", challenge_hex.len());
        let response = build_legacy_response(password, &challenge_hex)?;

        let login_sentences = self
            .raw_command(vec![
                "/login".to_string(),
                format!("=name={}", username),
                format!("=response={}", response),
            ])
            .await
            .map_err(|error| {
                AppError::RouterOs(format!("Legacy login response submission failed: {error}"))
            })?;

        for sentence in &login_sentences {
            if let Some(message) = sentence.get("message") {
                tracing::warn!("Login message: {}", message);
            }
        }
        tracing::debug!("Login successful (legacy method)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::build_legacy_response;

    #[test]
    fn test_build_legacy_response_known_values() {
        let response = build_legacy_response("secret", "0f0e0d0c0b0a09080706050403020100")
            .expect("response should build");
        assert_eq!(response, "006207c72a4341e4f21771ae7f77036fed");
    }

    #[test]
    fn test_build_legacy_response_invalid_hex() {
        let result = build_legacy_response("secret", "zz");
        assert!(result.is_err());
    }
}
