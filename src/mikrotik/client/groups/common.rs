// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Shared helpers for client groups.

use std::collections::HashMap;

pub(crate) fn parse_count_only(sentences: &[HashMap<String, String>]) -> Option<u64> {
    sentences.iter().find_map(|sentence| {
        sentence
            .get("ret")
            .and_then(|value| value.parse::<u64>().ok())
    })
}
