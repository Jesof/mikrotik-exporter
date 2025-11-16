// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Type definitions for MikroTik metrics

/// Statistics for a network interface
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub running: bool,
}

/// System resource information from a `MikroTik` router
#[derive(Debug, Clone)]
pub struct SystemResource {
    pub uptime: String,
    pub cpu_load: u64,
    pub free_memory: u64,
    pub total_memory: u64,
    pub version: String,
    pub board_name: String,
}

/// Complete metrics snapshot from a router
#[derive(Debug, Clone)]
pub struct RouterMetrics {
    pub router_name: String,
    pub interfaces: Vec<InterfaceStats>,
    pub system: SystemResource,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_stats_creation() {
        let stats = InterfaceStats {
            name: "ether1".to_string(),
            rx_bytes: 1000,
            tx_bytes: 2000,
            rx_packets: 10,
            tx_packets: 20,
            rx_errors: 0,
            tx_errors: 0,
            running: true,
        };

        assert_eq!(stats.name, "ether1");
        assert_eq!(stats.rx_bytes, 1000);
        assert_eq!(stats.tx_bytes, 2000);
        assert!(stats.running);
    }

    #[test]
    fn test_system_resource_creation() {
        let resource = SystemResource {
            uptime: "1d2h3m4s".to_string(),
            cpu_load: 50,
            free_memory: 1024 * 1024 * 512,
            total_memory: 1024 * 1024 * 1024,
            version: "7.10".to_string(),
            board_name: "RB750Gr3".to_string(),
        };

        assert_eq!(resource.uptime, "1d2h3m4s");
        assert_eq!(resource.cpu_load, 50);
        assert_eq!(resource.version, "7.10");
        assert_eq!(resource.board_name, "RB750Gr3");
    }

    #[test]
    fn test_router_metrics_creation() {
        let metrics = RouterMetrics {
            router_name: "main-router".to_string(),
            interfaces: vec![InterfaceStats {
                name: "ether1".to_string(),
                rx_bytes: 1000,
                tx_bytes: 2000,
                rx_packets: 10,
                tx_packets: 20,
                rx_errors: 0,
                tx_errors: 0,
                running: true,
            }],
            system: SystemResource {
                uptime: "1d".to_string(),
                cpu_load: 10,
                free_memory: 1024,
                total_memory: 2048,
                version: "7.10".to_string(),
                board_name: "test".to_string(),
            },
        };

        assert_eq!(metrics.router_name, "main-router");
        assert_eq!(metrics.interfaces.len(), 1);
        assert_eq!(metrics.interfaces[0].name, "ether1");
        assert_eq!(metrics.system.version, "7.10");
    }

    #[test]
    fn test_interface_stats_clone() {
        let stats = InterfaceStats {
            name: "ether1".to_string(),
            rx_bytes: 1000,
            tx_bytes: 2000,
            rx_packets: 10,
            tx_packets: 20,
            rx_errors: 0,
            tx_errors: 0,
            running: true,
        };

        let cloned = stats.clone();
        assert_eq!(stats.name, cloned.name);
        assert_eq!(stats.rx_bytes, cloned.rx_bytes);
    }
}
