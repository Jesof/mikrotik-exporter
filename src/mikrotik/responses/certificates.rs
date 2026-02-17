// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Certificate parsing utilities

use crate::mikrotik::types::CertificateStats;
use chrono::{NaiveDate, Utc};
use std::collections::HashMap;

pub(crate) fn parse_certificates(sentences: &[HashMap<String, String>]) -> Vec<CertificateStats> {
    let mut certificates = Vec::new();

    for sentence in sentences {
        let name = match sentence.get("name") {
            Some(n) if !n.is_empty() => n.clone(),
            _ => continue,
        };

        // Try to get expiration date from "invalid-after" field first (new format)
        // Fall back to "expiration" field (legacy format)
        let expiry_str = match sentence.get("invalid-after") {
            Some(exp) if !exp.is_empty() => exp,
            _ => match sentence.get("expiration") {
                Some(exp) if !exp.is_empty() => exp,
                _ => continue,
            },
        };

        let days_until_expiry = parse_certificate_expiry(expiry_str);

        if days_until_expiry == 0 {
            continue;
        }

        certificates.push(CertificateStats {
            name,
            days_until_expiry,
        });
    }

    certificates
}

fn parse_certificate_expiry(expiry_str: &str) -> i64 {
    let parts: Vec<&str> = expiry_str.split(' ').collect();
    if parts.is_empty() {
        return 0;
    }

    let date_part = parts[0];

    // Try to parse ISO format first (YYYY-MM-DD)
    if let Some(days) = parse_iso_date_format(date_part) {
        return days;
    }

    // Fall back to legacy format (MMM/DD/YYYY)
    parse_legacy_date_format(date_part)
}

fn parse_iso_date_format(date_part: &str) -> Option<i64> {
    let date_components: Vec<&str> = date_part.split('-').collect();
    if date_components.len() != 3 {
        return None;
    }

    let year = date_components[0].parse::<i32>().ok()?;
    let month = date_components[1].parse::<u32>().ok()?;
    let day = date_components[2].parse::<u32>().ok()?;

    let expiry_date = NaiveDate::from_ymd_opt(year, month, day)?;
    let current_date = Utc::now().date_naive();
    let duration = expiry_date.signed_duration_since(current_date);
    let days = duration.num_days();

    // Skip expired certificates
    if days <= 0 {
        return Some(0);
    }

    Some(days)
}

fn parse_legacy_date_format(date_part: &str) -> i64 {
    let date_components: Vec<&str> = date_part.split('/').collect();
    if date_components.len() != 3 {
        return 0;
    }

    let month_str = date_components[0];
    let day_str = date_components[1];
    let year_str = date_components[2];

    let month_num = match month_str {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return 0,
    };

    let day = match day_str.parse::<u32>() {
        Ok(d) => d,
        Err(_) => return 0,
    };

    let year = match year_str.parse::<i32>() {
        Ok(y) => y,
        Err(_) => return 0,
    };

    let expiry_date = match NaiveDate::from_ymd_opt(year, month_num, day) {
        Some(date) => date,
        None => return 0,
    };

    let current_date = Utc::now().date_naive();
    let duration = expiry_date.signed_duration_since(current_date);
    let days = duration.num_days();

    // Skip expired certificates (return 0 to indicate they should be skipped)
    if days <= 0 {
        return 0;
    }

    days
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_certificates_legacy_format() {
        let mut sentence1 = HashMap::new();
        sentence1.insert("name".to_string(), "cert1".to_string());
        // Use a future date that's definitely in the future
        sentence1.insert("expiration".to_string(), "Jan/01/2030 12:00:00".to_string());

        let mut sentence2 = HashMap::new();
        sentence2.insert("name".to_string(), "cert2".to_string());
        // Use another future date
        sentence2.insert("expiration".to_string(), "Dec/31/2029 23:59:59".to_string());

        let sentences = vec![sentence1, sentence2];
        let certificates = parse_certificates(&sentences);

        assert_eq!(certificates.len(), 2);
        assert_eq!(certificates[0].name, "cert1");
        assert_eq!(certificates[1].name, "cert2");
    }

    #[test]
    fn test_parse_certificates_new_format() {
        let mut sentence1 = HashMap::new();
        sentence1.insert("name".to_string(), "cert1".to_string());
        // Use a future date that's definitely in the future in ISO format
        sentence1.insert(
            "invalid-after".to_string(),
            "2030-01-01 12:00:00".to_string(),
        );

        let mut sentence2 = HashMap::new();
        sentence2.insert("name".to_string(), "cert2".to_string());
        // Use another future date in ISO format
        sentence2.insert(
            "invalid-after".to_string(),
            "2029-12-31 23:59:59".to_string(),
        );

        let sentences = vec![sentence1, sentence2];
        let certificates = parse_certificates(&sentences);

        assert_eq!(certificates.len(), 2);
        assert_eq!(certificates[0].name, "cert1");
        assert_eq!(certificates[1].name, "cert2");
    }

    #[test]
    fn test_parse_certificates_prefer_new_format() {
        let mut sentence = HashMap::new();
        sentence.insert("name".to_string(), "cert1".to_string());
        // Both fields present - should prefer "invalid-after"
        sentence.insert(
            "invalid-after".to_string(),
            "2030-01-01 12:00:00".to_string(),
        );
        sentence.insert("expiration".to_string(), "Jan/01/2025 12:00:00".to_string());

        let sentences = vec![sentence];
        let certificates = parse_certificates(&sentences);

        assert_eq!(certificates.len(), 1);
        assert_eq!(certificates[0].name, "cert1");
    }

    #[test]
    fn test_parse_certificates_with_expired() {
        let mut sentence = HashMap::new();
        sentence.insert("name".to_string(), "expired-cert".to_string());
        sentence.insert("expiration".to_string(), "Jan/01/2020 12:00:00".to_string());

        let sentences = vec![sentence];
        let certificates = parse_certificates(&sentences);

        // Expired certificates should be skipped (days_until_expiry would be <= 0)
        assert_eq!(certificates.len(), 0);
    }

    #[test]
    fn test_parse_certificate_expiry_valid() {
        // Test a future date
        let future_date = "Dec/31/2030 23:59:59";
        let days = parse_certificate_expiry(future_date);
        // Should be a positive number of days in the future
        assert!(days > 0);
    }

    #[test]
    fn test_parse_certificate_expiry_invalid_format() {
        // Test various invalid formats
        assert_eq!(parse_certificate_expiry(""), 0);
        assert_eq!(parse_certificate_expiry("invalid-format"), 0);
        assert_eq!(parse_certificate_expiry("13/01/2025"), 0); // Invalid month
        assert_eq!(parse_certificate_expiry("Jan/32/2025"), 0); // Invalid day
        assert_eq!(parse_certificate_expiry("Jan/01/invalid"), 0); // Invalid year
    }

    #[test]
    fn test_parse_certificates_skip_invalid() {
        let mut sentence = HashMap::new();
        sentence.insert("name".to_string(), "invalid".to_string());
        sentence.insert("expiration".to_string(), "invalid-date".to_string());

        let sentences = vec![sentence];
        let certificates = parse_certificates(&sentences);

        assert!(certificates.is_empty());
    }

    #[test]
    fn test_parse_certificates_skip_missing_fields() {
        let sentences = vec![HashMap::new()];

        let certificates = parse_certificates(&sentences);
        assert!(certificates.is_empty());
    }
}
