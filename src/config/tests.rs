// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Unit tests for configuration module

#[cfg(test)]
mod test {
    use super::super::*;
    use secrecy::ExposeSecret;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    struct EnvVarGuard {
        key: String,
        prev: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            Self {
                key: key.to_string(),
                prev,
            }
        }

        fn unset(key: &str) -> Self {
            let prev = std::env::var(key).ok();
            unsafe {
                std::env::remove_var(key);
            }
            Self {
                key: key.to_string(),
                prev,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(value) => unsafe {
                    std::env::set_var(&self.key, value);
                },
                None => unsafe {
                    std::env::remove_var(&self.key);
                },
            }
        }
    }

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        match LOCK.get_or_init(|| Mutex::new(())).lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.server_addr, "0.0.0.0:9090");
        assert_eq!(config.collection_interval_secs, 30);
        assert!(config.routers.is_empty());
    }

    #[test]
    fn test_router_config_deserialize() {
        let json = r#"{
            "name": "test-router",
            "address": "192.168.1.1:8728",
            "username": "admin",
            "password": "secret"
        }"#;

        let router: RouterConfig = serde_json::from_str(json).unwrap();
        assert_eq!(router.name, "test-router");
        assert_eq!(router.address, "192.168.1.1:8728");
        assert_eq!(router.username, "admin");
        assert_eq!(router.password.expose_secret(), "secret");
    }

    #[test]
    fn test_multiple_routers_deserialize() {
        let json = r#"[
            {
                "name": "router1",
                "address": "192.168.1.1:8728",
                "username": "admin",
                "password": "pass1"
            },
            {
                "name": "router2",
                "address": "192.168.2.1:8728",
                "username": "admin",
                "password": "pass2"
            }
        ]"#;

        let routers: Vec<RouterConfig> = serde_json::from_str(json).unwrap();
        assert_eq!(routers.len(), 2);
        assert_eq!(routers[0].name, "router1");
        assert_eq!(routers[1].name, "router2");
    }

    #[test]
    fn test_router_config_validate_valid() {
        let config = RouterConfig {
            name: "test-router".to_string(),
            address: "192.168.1.1:8728".to_string(),
            username: "admin".to_string(),
            password: secrecy::SecretString::new("password".to_string().into()),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_router_config_validate_empty_name() {
        let config = RouterConfig {
            name: "  ".to_string(),
            address: "192.168.1.1:8728".to_string(),
            username: "admin".to_string(),
            password: "password".to_string().into(),
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("name cannot be empty"));
    }

    #[test]
    fn test_router_config_validate_invalid_address() {
        let config = RouterConfig {
            name: "test-router".to_string(),
            address: "192.168.1.1".to_string(), // Missing port
            username: "admin".to_string(),
            password: "password".to_string().into(),
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 'host:port'"));
    }

    #[test]
    fn test_router_config_validate_empty_username() {
        let config = RouterConfig {
            name: "test-router".to_string(),
            address: "192.168.1.1:8728".to_string(),
            username: "  ".to_string(),
            password: "password".to_string().into(),
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Username cannot be empty"));
    }

    #[test]
    fn test_from_env_defaults_without_router() {
        let _lock = env_lock();
        let _guards = vec![
            EnvVarGuard::unset("SERVER_ADDR"),
            EnvVarGuard::unset("ROUTERS_CONFIG"),
            EnvVarGuard::unset("ROUTEROS_ADDRESS"),
            EnvVarGuard::unset("ROUTEROS_USERNAME"),
            EnvVarGuard::unset("ROUTEROS_PASSWORD"),
            EnvVarGuard::unset("COLLECTION_INTERVAL_SECONDS"),
            EnvVarGuard::unset("STARTUP_CONNECTIVITY_TEST"),
            EnvVarGuard::unset("STARTUP_CONNECTIVITY_TIMEOUT_SECS"),
            EnvVarGuard::unset("STRICT_STARTUP_MODE"),
        ];

        let config = Config::from_env();
        assert_eq!(config.server_addr, "0.0.0.0:9090");
        assert_eq!(config.collection_interval_secs, 30);
        assert!(config.routers.is_empty());
        assert!(!config.startup_connectivity_test);
        assert_eq!(config.startup_connectivity_timeout_secs, 10);
        assert!(!config.strict_startup_mode);
    }

    #[test]
    fn test_from_env_with_routers_config() {
        let _lock = env_lock();
        let routers_json = r#"[
            {
                "name": "edge",
                "address": "10.0.0.1:8728",
                "username": "admin",
                "password": "secret"
            }
        ]"#;
        let _guards = vec![
            EnvVarGuard::set("SERVER_ADDR", "127.0.0.1:19090"),
            EnvVarGuard::set("ROUTERS_CONFIG", routers_json),
            EnvVarGuard::set("COLLECTION_INTERVAL_SECONDS", "45"),
            EnvVarGuard::set("STARTUP_CONNECTIVITY_TEST", "true"),
            EnvVarGuard::set("STARTUP_CONNECTIVITY_TIMEOUT_SECS", "20"),
            EnvVarGuard::set("STRICT_STARTUP_MODE", "true"),
            EnvVarGuard::unset("ROUTEROS_ADDRESS"),
            EnvVarGuard::unset("ROUTEROS_USERNAME"),
            EnvVarGuard::unset("ROUTEROS_PASSWORD"),
        ];

        let config = Config::from_env();
        assert_eq!(config.server_addr, "127.0.0.1:19090");
        assert_eq!(config.collection_interval_secs, 45);
        assert!(config.startup_connectivity_test);
        assert_eq!(config.startup_connectivity_timeout_secs, 20);
        assert!(config.strict_startup_mode);
        assert_eq!(config.routers.len(), 1);
        assert_eq!(config.routers[0].name, "edge");
        assert_eq!(config.routers[0].address, "10.0.0.1:8728");
    }

    #[test]
    fn test_from_env_filters_invalid_and_duplicates() {
        let _lock = env_lock();
        let routers_json = r#"[
            {
                "name": "core",
                "address": "10.0.0.2:8728",
                "username": "admin",
                "password": "secret"
            },
            {
                "name": "core",
                "address": "10.0.0.3:8728",
                "username": "admin",
                "password": "secret"
            },
            {
                "name": "  " ,
                "address": "10.0.0.4",
                "username": "admin",
                "password": "secret"
            }
        ]"#;
        let _guards = [
            EnvVarGuard::set("ROUTERS_CONFIG", routers_json),
            EnvVarGuard::unset("ROUTEROS_ADDRESS"),
            EnvVarGuard::unset("ROUTEROS_USERNAME"),
            EnvVarGuard::unset("ROUTEROS_PASSWORD"),
        ];

        let config = Config::from_env();
        assert_eq!(config.routers.len(), 1);
        assert_eq!(config.routers[0].name, "core");
        assert_eq!(config.routers[0].address, "10.0.0.2:8728");
    }

    #[test]
    fn test_from_env_legacy_router_defaults() {
        let _lock = env_lock();
        let _guards = [
            EnvVarGuard::set("ROUTEROS_ADDRESS", "192.168.88.1:8728"),
            EnvVarGuard::unset("ROUTERS_CONFIG"),
            EnvVarGuard::unset("ROUTEROS_USERNAME"),
            EnvVarGuard::unset("ROUTEROS_PASSWORD"),
        ];

        let config = Config::from_env();
        assert_eq!(config.routers.len(), 1);
        assert_eq!(config.routers[0].name, "default");
        assert_eq!(config.routers[0].username, "admin");
        assert_eq!(config.routers[0].password.expose_secret(), "");
    }

    #[test]
    fn test_from_env_legacy_router_custom_creds() {
        let _lock = env_lock();
        let _guards = [
            EnvVarGuard::set("ROUTEROS_ADDRESS", "192.168.88.2:8728"),
            EnvVarGuard::set("ROUTEROS_USERNAME", "root"),
            EnvVarGuard::set("ROUTEROS_PASSWORD", "topsecret"),
            EnvVarGuard::unset("ROUTERS_CONFIG"),
        ];

        let config = Config::from_env();
        assert_eq!(config.routers.len(), 1);
        assert_eq!(config.routers[0].name, "default");
        assert_eq!(config.routers[0].username, "root");
        assert_eq!(config.routers[0].password.expose_secret(), "topsecret");
    }
}
