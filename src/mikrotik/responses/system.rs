// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use super::common::{parse_u64_field, required_field};
use crate::metrics::parsers::parse_uptime_to_seconds;
use crate::mikrotik::types::SystemResource;
use crate::prelude::{AppError, Result};
use std::collections::HashMap;

pub(crate) fn parse_system(sentences: &[HashMap<String, String>]) -> Result<SystemResource> {
    let [row] = sentences else {
        return Err(AppError::InvalidSnapshot(
            "expected one system resource row".into(),
        ));
    };
    let system = SystemResource {
        uptime: required_field(row, "uptime")?.into(),
        cpu_load: parse_u64_field(row, "cpu-load", "system")?,
        free_memory: parse_u64_field(row, "free-memory", "system")?,
        total_memory: parse_u64_field(row, "total-memory", "system")?,
        version: required_field(row, "version")?.into(),
        board_name: required_field(row, "board-name")?.into(),
    };
    if parse_uptime_to_seconds(&system.uptime).is_none_or(|n| n > i64::MAX as u64)
        || system.cpu_load > 100
        || system.free_memory > system.total_memory
        || system.total_memory > i64::MAX as u64
    {
        return Err(AppError::InvalidSnapshot(
            "invalid system resource bounds or uptime".into(),
        ));
    }
    Ok(system)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_system_rejects_missing_invalid_and_out_of_range_fields() {
        let row: HashMap<String, String> = [
            ("uptime", "1d"),
            ("cpu-load", "25"),
            ("free-memory", "512"),
            ("total-memory", "1024"),
            ("version", "7.10"),
            ("board-name", "test"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        assert_eq!(
            parse_system(std::slice::from_ref(&row)).unwrap().cpu_load,
            25
        );
        assert!(parse_system(&[]).is_err());
        for (field, value) in [
            ("uptime", "garbage"),
            ("cpu-load", "101"),
            ("free-memory", "2048"),
            ("total-memory", "invalid"),
        ] {
            let mut invalid = row.clone();
            invalid.insert(field.into(), value.into());
            assert!(parse_system(&[invalid]).is_err());
        }
    }
}
