// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use crate::prelude::{AppError, Result};
use std::collections::HashMap;

pub(super) fn required_field<'a>(
    sentence: &'a HashMap<String, String>,
    field: &str,
) -> Result<&'a str> {
    sentence
        .get(field)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| AppError::InvalidSnapshot(format!("missing field {field}")))
}

pub(super) fn parse_u64_field(
    sentence: &HashMap<String, String>,
    field: &'static str,
    context: &'static str,
) -> Result<u64> {
    required_field(sentence, field)?.parse().map_err(|_| {
        AppError::InvalidSnapshot(format!("invalid numeric field {field} in {context}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numeric_fields_reject_missing_malformed_and_overflow() {
        let mut row = HashMap::new();
        assert!(parse_u64_field(&row, "rx", "test").is_err());
        for value in ["", "abc", "-1", "18446744073709551616"] {
            row.insert("rx".into(), value.into());
            assert!(matches!(
                parse_u64_field(&row, "rx", "test"),
                Err(AppError::InvalidSnapshot(_))
            ));
        }
        row.insert("rx".into(), "0".into());
        assert_eq!(parse_u64_field(&row, "rx", "test").unwrap(), 0);
    }
}
