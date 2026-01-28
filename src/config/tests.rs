// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Unit tests for configuration module

#[cfg(test)]
mod test {
    use super::super::*;

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
        assert_eq!(router.password, "secret");
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
            password: "password".to_string(),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_router_config_validate_empty_name() {
        let config = RouterConfig {
            name: "  ".to_string(),
            address: "192.168.1.1:8728".to_string(),
            username: "admin".to_string(),
            password: "password".to_string(),
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
            password: "password".to_string(),
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
            password: "password".to_string(),
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Username cannot be empty"));
    }
}
