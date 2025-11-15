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
