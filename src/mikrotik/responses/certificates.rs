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

        let expiry_str = match sentence.get("expiration") {
            Some(exp) if !exp.is_empty() => exp,
            _ => continue,
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
    duration.num_days()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_certificates() {
        let mut sentence1 = HashMap::new();
        sentence1.insert("name".to_string(), "cert1".to_string());
        sentence1.insert("expiration".to_string(), "Jan/01/2025 12:00:00".to_string());

        let mut sentence2 = HashMap::new();
        sentence2.insert("name".to_string(), "cert2".to_string());
        sentence2.insert("expiration".to_string(), "Dec/31/2024 23:59:59".to_string());

        let sentences = vec![sentence1, sentence2];
        let certificates = parse_certificates(&sentences);

        assert_eq!(certificates.len(), 2);
        assert_eq!(certificates[0].name, "cert1");
        assert_eq!(certificates[1].name, "cert2");
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
