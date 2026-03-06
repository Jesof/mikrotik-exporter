// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! System resource parsing

use crate::mikrotik::types::SystemResource;
use std::collections::HashMap;

use super::common::parse_u64_field;

pub(crate) fn parse_system(sentences: &[HashMap<String, String>]) -> SystemResource {
    let first_opt = sentences.iter().find(|s| s.contains_key("version"));
    let empty = HashMap::new();
    let first = first_opt.unwrap_or(&empty);
    SystemResource {
        uptime: first
            .get("uptime")
            .cloned()
            .unwrap_or_else(|| "0s".to_string()),
        cpu_load: parse_u64_field(first, "cpu-load", "system resources"),
        free_memory: parse_u64_field(first, "free-memory", "system resources"),
        total_memory: parse_u64_field(first, "total-memory", "system resources"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_system_complete() {
        let mut data = HashMap::new();
        data.insert("version".to_string(), "7.10".to_string());
        data.insert("uptime".to_string(), "1w2d3h4m5s".to_string());
        data.insert("cpu-load".to_string(), "25".to_string());
        data.insert("free-memory".to_string(), "524288000".to_string());
        data.insert("total-memory".to_string(), "1073741824".to_string());
        data.insert("board-name".to_string(), "RB750Gr3".to_string());

        let result = parse_system(&[data]);

        assert_eq!(result.version, "7.10");
        assert_eq!(result.uptime, "1w2d3h4m5s");
        assert_eq!(result.cpu_load, 25);
        assert_eq!(result.free_memory, 524_288_000);
        assert_eq!(result.total_memory, 1_073_741_824);
        assert_eq!(result.board_name, "RB750Gr3");
    }

    #[test]
    fn test_parse_system_empty() {
        let result = parse_system(&[]);
        assert_eq!(result.version, "unknown");
        assert_eq!(result.uptime, "0s");
        assert_eq!(result.cpu_load, 0);
        assert_eq!(result.board_name, "unknown");
    }

    #[test]
    fn test_parse_system_partial() {
        let mut data = HashMap::new();
        data.insert("version".to_string(), "7.10".to_string());

        let result = parse_system(&[data]);

        assert_eq!(result.version, "7.10");
        assert_eq!(result.uptime, "0s");
        assert_eq!(result.cpu_load, 0);
    }
}
