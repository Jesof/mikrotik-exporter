// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use super::common::required_field;
use crate::mikrotik::SnapshotError;
use crate::mikrotik::types::CertificateStats;
use crate::prelude::{AppError, Result};
use chrono::{NaiveDate, Utc};
use std::collections::HashMap;

pub(crate) fn parse_certificates(
    sentences: &[HashMap<String, String>],
) -> Result<Vec<CertificateStats>> {
    let mut certificates = Vec::new();
    for row in sentences {
        let id = required_field(row, ".id")?;
        let name = required_field(row, "name")?;
        let expiry = row
            .get("invalid-after")
            .filter(|s| !s.is_empty())
            .or_else(|| row.get("expiration").filter(|s| !s.is_empty()));
        let Some(expiry) = expiry else {
            continue;
        };
        let date = parse_expiry_date(expiry).ok_or(AppError::InvalidSnapshot(
            SnapshotError::InvalidCertificateExpiry,
        ))?;
        certificates.push(CertificateStats {
            id: id.into(),
            name: name.into(),
            days_until_expiry: date
                .signed_duration_since(Utc::now().date_naive())
                .num_days(),
        });
    }
    Ok(certificates)
}

fn parse_expiry_date(value: &str) -> Option<NaiveDate> {
    let date = value.split_whitespace().next()?;
    NaiveDate::parse_from_str(date, "%Y-%m-%d")
        .or_else(|_| NaiveDate::parse_from_str(date, "%b/%d/%Y"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_certificate_expiry_formats_and_validation() {
        assert_eq!(
            parse_expiry_date("2030-01-01 12:00:00"),
            parse_expiry_date("jan/01/2030 12:00:00")
        );
        assert!(parse_expiry_date("Jan/32/2030").is_none());
        let mut row: HashMap<String, String> = [
            (".id", "*1"),
            ("name", "cert"),
            ("invalid-after", "2020-01-01 12:00:00"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        assert!(parse_certificates(std::slice::from_ref(&row)).unwrap()[0].days_until_expiry < 0);
        row.insert("invalid-after".into(), Utc::now().date_naive().to_string());
        assert_eq!(
            parse_certificates(std::slice::from_ref(&row)).unwrap()[0].days_until_expiry,
            0
        );
        row.insert("invalid-after".into(), "garbage".into());
        assert!(parse_certificates(std::slice::from_ref(&row)).is_err());
        row.remove("invalid-after");
        assert!(parse_certificates(&[row]).unwrap().is_empty());
        assert!(parse_certificates(&[]).unwrap().is_empty());
        assert!(parse_certificates(&[HashMap::new()]).is_err());
    }
}
