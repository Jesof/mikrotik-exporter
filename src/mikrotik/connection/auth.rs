// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! `RouterOS` authentication

use md5::compute as md5_compute;

use super::RouterOsConnection;

fn build_legacy_response(
    password: &str,
    challenge_hex: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let challenge = hex::decode(challenge_hex)?;

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
    pub(crate) async fn login(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
                // Check for error messages
                for s in &sentences {
                    if let Some(msg) = s.get("message") {
                        if msg.contains("failure") || msg.contains("invalid") {
                            tracing::trace!("Login failed with message: {}", msg);
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
        tracing::trace!("Requesting challenge for legacy login");
        let sentences = self.raw_command(vec!["/login".to_string()]).await?;
        let mut challenge_hex = None;
        for s in sentences {
            if let Some(ret) = s.get("ret") {
                challenge_hex = Some(ret.clone());
            }
        }
        let challenge_hex = challenge_hex.ok_or("No challenge 'ret' received")?;
        tracing::trace!("Challenge received, length: {}", challenge_hex.len());
        let response = build_legacy_response(password, &challenge_hex)?;

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
