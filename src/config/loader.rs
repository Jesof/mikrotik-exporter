// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use secrecy::SecretString;

use super::{RouterConfig, defaults, env_vars};

pub(crate) fn load_router_configs() -> Vec<RouterConfig> {
    if let Ok(config_json) = std::env::var(env_vars::ROUTERS_CONFIG) {
        return serde_json::from_str(&config_json).unwrap_or_else(|error| {
            tracing::warn!(
                "Failed to parse ROUTERS_CONFIG: {}. Using empty list.",
                error
            );
            Vec::new()
        });
    }

    load_legacy_router_config().into_iter().collect()
}

fn load_legacy_router_config() -> Option<RouterConfig> {
    let address = std::env::var(env_vars::ROUTEROS_ADDRESS).ok();
    let username = string_env_or_default(env_vars::ROUTEROS_USERNAME, defaults::ROUTEROS_USERNAME);
    let password = string_env_or_default(env_vars::ROUTEROS_PASSWORD, defaults::ROUTEROS_PASSWORD);
    let password_secret = SecretString::new(password.into_boxed_str());

    if let Some(addr) = address {
        Some(RouterConfig {
            name: "default".to_string(),
            address: addr,
            username,
            password: password_secret,
        })
    } else {
        tracing::warn!(
            "No router configuration found. Service will start but /metrics will be empty."
        );
        None
    }
}

pub(crate) fn validate_and_deduplicate_routers(routers: Vec<RouterConfig>) -> Vec<RouterConfig> {
    let validated: Vec<RouterConfig> = routers
        .into_iter()
        .filter(|router| match router.validate() {
            Ok(()) => true,
            Err(error) => {
                tracing::error!("Invalid router '{}': {}", router.name, error);
                tracing::warn!("Skipping invalid router: {}", router.name);
                false
            }
        })
        .collect();

    let mut seen_names = std::collections::HashSet::new();
    validated
        .into_iter()
        .filter(|router| {
            if seen_names.contains(&router.name) {
                tracing::error!(
                    "Duplicate router name '{}' found. Router names must be unique.",
                    router.name
                );
                false
            } else {
                seen_names.insert(router.name.clone());
                true
            }
        })
        .collect()
}

pub(crate) fn parse_env_or_default<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or(default)
}

pub(crate) fn string_env_or_default(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
