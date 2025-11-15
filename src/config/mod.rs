//! Configuration module
//!
//! Handles loading and parsing application configuration from environment variables.

use serde::Deserialize;

#[cfg(test)]
mod tests;

/// Значения по умолчанию для конфигурации
pub mod defaults {
    pub const SERVER_ADDR: &str = "0.0.0.0:9090";
    pub const ROUTEROS_USERNAME: &str = "admin";
    pub const ROUTEROS_PASSWORD: &str = "";
}

/// Переменные окружения
pub mod env_vars {
    pub const SERVER_ADDR: &str = "SERVER_ADDR";
    pub const ROUTERS_CONFIG: &str = "ROUTERS_CONFIG";
}

/// Конфигурация одного `MikroTik` роутера
#[derive(Debug, Clone, Deserialize)]
pub struct RouterConfig {
    pub name: String,
    pub address: String,
    pub username: String,
    pub password: String,
}

/// Конфигурация приложения
#[derive(Debug, Clone)]
pub struct Config {
    pub server_addr: String,
    pub routers: Vec<RouterConfig>,
    pub collection_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server_addr: defaults::SERVER_ADDR.to_string(),
            routers: vec![],
            collection_interval_secs: 30,
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();

        let server_addr = std::env::var(env_vars::SERVER_ADDR)
            .unwrap_or_else(|_| defaults::SERVER_ADDR.to_string());

        // Загружаем конфигурацию роутеров из JSON
        let routers = if let Ok(config_json) = std::env::var(env_vars::ROUTERS_CONFIG) {
            serde_json::from_str(&config_json).unwrap_or_else(|e| {
                tracing::warn!("Failed to parse ROUTERS_CONFIG: {}. Using empty list.", e);
                vec![]
            })
        } else {
            // Fallback: используем старые переменные окружения для одного роутера
            let address = std::env::var("ROUTEROS_ADDRESS").ok();
            let username = std::env::var("ROUTEROS_USERNAME")
                .unwrap_or_else(|_| defaults::ROUTEROS_USERNAME.to_string());
            let password = std::env::var("ROUTEROS_PASSWORD")
                .unwrap_or_else(|_| defaults::ROUTEROS_PASSWORD.to_string());

            if let Some(addr) = address {
                vec![RouterConfig {
                    name: "default".to_string(),
                    address: addr,
                    username,
                    password,
                }]
            } else {
                tracing::warn!(
                    "No router configuration found. Service will start but /metrics will be empty."
                );
                vec![]
            }
        };

        let collection_interval_secs = std::env::var("COLLECTION_INTERVAL_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);

        Config {
            server_addr,
            routers,
            collection_interval_secs,
        }
    }
}
