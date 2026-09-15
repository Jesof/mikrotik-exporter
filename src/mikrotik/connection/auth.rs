// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use crate::prelude::{AppError, Result};
use md5::compute as md5_compute;

use super::RouterOsConnection;

fn build_legacy_response(password: &str, challenge_hex: &str) -> Result<String> {
    if challenge_hex.len() != 32 {
        return Err(AppError::Authentication("invalid challenge length".into()));
    }
    let challenge = hex::decode(challenge_hex)
        .map_err(|_| AppError::Authentication("invalid challenge encoding".into()))?;
    let mut data = Vec::with_capacity(1 + password.len() + challenge.len());
    data.push(0u8);
    data.extend_from_slice(password.as_bytes());
    data.extend_from_slice(&challenge);
    let digest = md5_compute(&data);
    Ok(format!("00{}", hex::encode(digest.0)))
}

impl RouterOsConnection {
    pub(crate) async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        let response = self
            .raw_command(vec![
                "/login".into(),
                format!("=name={username}"),
                format!("=password={password}"),
            ])
            .await?;
        if !response.records.is_empty() {
            self.dirty = true;
            return Err(AppError::Authentication("unexpected login records".into()));
        }
        if let Some(challenge) = response.done.get("ret") {
            let legacy = match build_legacy_response(password, challenge) {
                Ok(legacy) => legacy,
                Err(error) => {
                    self.dirty = true;
                    return Err(error);
                }
            };
            let response = self
                .raw_command(vec![
                    "/login".into(),
                    format!("=name={username}"),
                    format!("=response={legacy}"),
                ])
                .await?;
            if !response.records.is_empty() || response.done.contains_key("ret") {
                self.dirty = true;
                return Err(AppError::Authentication(
                    "challenge was not accepted".into(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::build_legacy_response;

    #[test]
    fn test_build_legacy_response_known_values() {
        let response = build_legacy_response("secret", "000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(response, "00925d25da4b1ffe731237818c4e1fcd57");
    }

    #[test]
    fn test_build_legacy_response_invalid_challenge() {
        for challenge in ["zz", "", "0000", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"] {
            assert!(build_legacy_response("secret", challenge).is_err());
        }
    }
}
