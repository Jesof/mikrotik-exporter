// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Environment and JSON configuration loading with strict parsing.

use crate::prelude::{AppError, Result};

use super::{RouterConfig, RouterTlsConfig, defaults, env_vars};

/// Loads router configurations from `ROUTERS_CONFIG` JSON or legacy env vars.
pub(crate) fn load_router_configs(
    lookup: &impl Fn(&str) -> Result<Option<String>>,
) -> Result<Vec<RouterConfig>> {
    if let Some(config_json) = lookup(env_vars::ROUTERS_CONFIG)? {
        return serde_json::from_str(&config_json).map_err(|error| {
            AppError::Config(format!(
                "Invalid ROUTERS_CONFIG JSON at line {}, column {}",
                error.line(),
                error.column()
            ))
        });
    }

    let Some(address) = lookup(env_vars::ROUTEROS_ADDRESS)? else {
        return Ok(Vec::new());
    };
    let tls = lookup(env_vars::ROUTEROS_TLS)?
        .map(|json| {
            serde_json::from_str::<RouterTlsConfig>(&json)
                .map_err(|_| AppError::Config("Invalid ROUTEROS_TLS JSON".into()))
        })
        .transpose()?;
    Ok(vec![RouterConfig {
        name: "default".to_string(),
        address,
        tls,
        username: string_env_or_default(
            lookup,
            env_vars::ROUTEROS_USERNAME,
            defaults::ROUTEROS_USERNAME,
        )?,
        password: string_env_or_default(
            lookup,
            env_vars::ROUTEROS_PASSWORD,
            defaults::ROUTEROS_PASSWORD,
        )?
        .into(),
    }])
}

/// Parses an environment variable or falls back to `default`; rejects invalid values.
pub(crate) fn parse_env_or_default<T: std::str::FromStr>(
    lookup: &impl Fn(&str) -> Result<Option<String>>,
    key: &str,
    default: T,
) -> Result<T> {
    match lookup(key)? {
        Some(value) => value
            .parse()
            .map_err(|_| AppError::Config(format!("Invalid {key}"))),
        None => Ok(default),
    }
}

/// Reads an environment variable as a string, or returns `default` when unset.
pub(crate) fn string_env_or_default(
    lookup: &impl Fn(&str) -> Result<Option<String>>,
    key: &str,
    default: &str,
) -> Result<String> {
    Ok(lookup(key)?.unwrap_or_else(|| default.to_string()))
}
