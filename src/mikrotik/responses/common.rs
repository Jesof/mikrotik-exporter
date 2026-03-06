// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Shared parsing helpers for `RouterOS` responses.

use std::collections::HashMap;

pub(super) fn parse_u64_field(
    sentence: &HashMap<String, String>,
    field: &'static str,
    context: &'static str,
) -> u64 {
    match sentence.get(field) {
        Some(value) => match value.parse::<u64>() {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::debug!(
                    "Invalid numeric field '{}' while parsing {}: '{}' ({})",
                    field,
                    context,
                    value,
                    error
                );
                0
            }
        },
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_u64_field_valid() {
        let mut sentence = HashMap::new();
        sentence.insert("rx-byte".to_string(), "123".to_string());

        assert_eq!(
            parse_u64_field(&sentence, "rx-byte", "interface stats"),
            123
        );
    }

    #[test]
    fn test_parse_u64_field_missing_or_invalid_defaults_to_zero() {
        let mut sentence = HashMap::new();
        sentence.insert("rx-byte".to_string(), "not-a-number".to_string());

        assert_eq!(parse_u64_field(&sentence, "rx-byte", "interface stats"), 0);
        assert_eq!(parse_u64_field(&sentence, "tx-byte", "interface stats"), 0);
    }
}
