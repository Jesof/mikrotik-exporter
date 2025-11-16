// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Unit tests for metrics parsing

#[cfg(test)]
mod test {
    use crate::metrics::labels::{InterfaceLabels, RouterLabels};
    use crate::metrics::parsers::parse_uptime_to_seconds;

    #[test]
    fn test_parse_uptime_hhmmss() {
        let uptime = parse_uptime_to_seconds("12:30:45");
        assert_eq!(uptime, 12 * 3600 + 30 * 60 + 45);
    }

    #[test]
    fn test_parse_uptime_mmss() {
        let uptime = parse_uptime_to_seconds("30:45");
        assert_eq!(uptime, 30 * 60 + 45);
    }

    #[test]
    fn test_parse_uptime_dhms() {
        let uptime = parse_uptime_to_seconds("2d5h30m15s");
        assert_eq!(uptime, 2 * 86400 + 5 * 3600 + 30 * 60 + 15);
    }

    #[test]
    fn test_parse_uptime_weeks() {
        let uptime = parse_uptime_to_seconds("1w2d");
        assert_eq!(uptime, 7 * 86400 + 2 * 86400);
    }

    #[test]
    fn test_parse_uptime_seconds_only() {
        let uptime = parse_uptime_to_seconds("300s");
        assert_eq!(uptime, 300);
    }

    #[test]
    fn test_parse_uptime_empty() {
        let uptime = parse_uptime_to_seconds("");
        assert_eq!(uptime, 0);
    }

    #[test]
    fn test_interface_labels_equality() {
        let label1 = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether1".to_string(),
        };
        let label2 = InterfaceLabels {
            router: "router1".to_string(),
            interface: "ether1".to_string(),
        };
        assert_eq!(label1, label2);
    }

    #[test]
    fn test_router_labels_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let label = RouterLabels {
            router: "router1".to_string(),
        };
        set.insert(label.clone());
        assert!(set.contains(&label));
    }
}
