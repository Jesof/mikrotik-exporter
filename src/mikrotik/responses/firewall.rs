// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Firewall rule parsing

use crate::mikrotik::types::FirewallRuleStats;
use std::collections::HashMap;

/// Parse firewall rules from `RouterOS` API responses
///
/// # Arguments
/// * `sentences` - Slice of `HashMap<String, String>` representing API responses
/// * `ip_version` - IP version string ("ipv4" or "ipv6")
/// * `section` - Firewall section ("filter", "nat", "mangle", "raw")
///
/// # Returns
/// Vector of `FirewallRuleStats` parsed from the API responses
pub(crate) fn parse_firewall_rules(
    sentences: &[HashMap<String, String>],
    ip_version: &str,
    section: &str,
) -> Vec<FirewallRuleStats> {
    let mut out = Vec::new();

    for s in sentences {
        // Skip disabled rules
        if s.get("disabled").is_some_and(|v| v == "true") {
            continue;
        }

        // Check if we have the required fields
        if let (Some(id), Some(chain), Some(action)) =
            (s.get(".id"), s.get("chain"), s.get("action"))
        {
            out.push(FirewallRuleStats {
                id: id.clone(),
                comment: s.get("comment").cloned().unwrap_or_default(),
                chain: chain.clone(),
                action: action.clone(),
                bytes: s.get("bytes").and_then(|v| v.parse().ok()).unwrap_or(0),
                packets: s.get("packets").and_then(|v| v.parse().ok()).unwrap_or(0),
                ip_version: ip_version.to_string(),
                section: section.to_string(),
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_firewall_rules_multiple() {
        let mut rule1 = HashMap::new();
        rule1.insert(".id".to_string(), "*1".to_string());
        rule1.insert("comment".to_string(), "Drop invalid".to_string());
        rule1.insert("chain".to_string(), "input".to_string());
        rule1.insert("action".to_string(), "accept".to_string());
        rule1.insert("bytes".to_string(), "1024".to_string());
        rule1.insert("packets".to_string(), "5".to_string());

        let mut rule2 = HashMap::new();
        rule2.insert(".id".to_string(), "*2".to_string());
        rule2.insert("chain".to_string(), "forward".to_string());
        rule2.insert("action".to_string(), "drop".to_string());
        rule2.insert("bytes".to_string(), "2048".to_string());
        rule2.insert("packets".to_string(), "10".to_string());

        let result = parse_firewall_rules(&[rule1, rule2], "ipv6", "filter");

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "*1");
        assert_eq!(result[0].comment, "Drop invalid");
        assert_eq!(result[0].chain, "input");
        assert_eq!(result[0].action, "accept");
        assert_eq!(result[0].bytes, 1024);
        assert_eq!(result[0].packets, 5);
        assert_eq!(result[0].ip_version, "ipv6");

        assert_eq!(result[1].id, "*2");
        assert_eq!(result[1].comment, "");
        assert_eq!(result[1].chain, "forward");
        assert_eq!(result[1].action, "drop");
        assert_eq!(result[1].bytes, 2048);
        assert_eq!(result[1].packets, 10);
        assert_eq!(result[1].ip_version, "ipv6");
        assert_eq!(result[1].section, "filter");
    }

    #[test]
    fn test_parse_firewall_rules_missing_values() {
        let mut rule = HashMap::new();
        rule.insert(".id".to_string(), "*1".to_string());
        rule.insert("chain".to_string(), "input".to_string());
        rule.insert("action".to_string(), "accept".to_string());
        // Missing bytes and packets

        let result = parse_firewall_rules(&[rule], "ipv4", "filter");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "*1");
        assert_eq!(result[0].comment, "");
        assert_eq!(result[0].chain, "input");
        assert_eq!(result[0].action, "accept");
        assert_eq!(result[0].bytes, 0); // Should default to 0
        assert_eq!(result[0].packets, 0); // Should default to 0
        assert_eq!(result[0].ip_version, "ipv4");
        assert_eq!(result[0].section, "filter");
    }

    #[test]
    fn test_parse_firewall_rules_disabled() {
        let mut rule = HashMap::new();
        rule.insert(".id".to_string(), "*1".to_string());
        rule.insert("chain".to_string(), "input".to_string());
        rule.insert("action".to_string(), "accept".to_string());
        rule.insert("bytes".to_string(), "1024".to_string());
        rule.insert("packets".to_string(), "5".to_string());
        rule.insert("disabled".to_string(), "true".to_string());

        let result = parse_firewall_rules(&[rule], "ipv4", "filter");

        assert_eq!(result.len(), 0); // Disabled rule should be skipped
    }

    #[test]
    fn test_parse_firewall_rules_no_id() {
        let mut rule = HashMap::new();
        rule.insert("chain".to_string(), "input".to_string());
        rule.insert("action".to_string(), "accept".to_string());
        rule.insert("bytes".to_string(), "1024".to_string());
        rule.insert("packets".to_string(), "5".to_string());

        let result = parse_firewall_rules(&[rule], "ipv4", "filter");

        assert_eq!(result.len(), 0); // Rule without .id should be skipped
    }

    #[test]
    fn test_parse_firewall_rules_no_chain() {
        let mut rule = HashMap::new();
        rule.insert(".id".to_string(), "*1".to_string());
        rule.insert("action".to_string(), "accept".to_string());
        rule.insert("bytes".to_string(), "1024".to_string());
        rule.insert("packets".to_string(), "5".to_string());

        let result = parse_firewall_rules(&[rule], "ipv4", "filter");

        assert_eq!(result.len(), 0); // Rule without chain should be skipped
    }

    #[test]
    fn test_parse_firewall_rules_no_action() {
        let mut rule = HashMap::new();
        rule.insert(".id".to_string(), "*1".to_string());
        rule.insert("chain".to_string(), "input".to_string());
        rule.insert("bytes".to_string(), "1024".to_string());
        rule.insert("packets".to_string(), "5".to_string());

        let result = parse_firewall_rules(&[rule], "ipv4", "filter");

        assert_eq!(result.len(), 0); // Rule without action should be skipped
    }

    #[test]
    fn test_parse_firewall_rules_empty() {
        let result = parse_firewall_rules(&[], "ipv4", "filter");
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_firewall_rules_with_stats_fields() {
        let mut rule = HashMap::new();
        rule.insert(".id".to_string(), "*1".to_string());
        rule.insert("chain".to_string(), "input".to_string());
        rule.insert("action".to_string(), "accept".to_string());
        rule.insert("bytes".to_string(), "1024000".to_string());
        rule.insert("packets".to_string(), "5000".to_string());

        let result = parse_firewall_rules(&[rule], "ipv4", "filter");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "*1");
        assert_eq!(result[0].bytes, 1_024_000);
        assert_eq!(result[0].packets, 5000);
    }

    #[test]
    fn test_parse_firewall_rules_without_stats_fields() {
        let mut rule = HashMap::new();
        rule.insert(".id".to_string(), "*1".to_string());
        rule.insert("chain".to_string(), "input".to_string());
        rule.insert("action".to_string(), "accept".to_string());
        // No bytes/packets fields

        let result = parse_firewall_rules(&[rule], "ipv4", "filter");

        assert_eq!(result.len(), 1);
        // Should default to 0 when fields are missing
        assert_eq!(result[0].bytes, 0);
        assert_eq!(result[0].packets, 0);
    }
}
