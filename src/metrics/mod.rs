//! Metrics registry and update logic.
use crate::mikrotik::RouterMetrics;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct InterfaceLabels {
    pub router: String,
    pub interface: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RouterLabels {
    pub router: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SystemInfoLabels {
    pub router: String,
    pub version: String,
    pub board: String,
}

/// Snapshot of interface counters (rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors)
type InterfaceSnapshot = (u64, u64, u64, u64, u64, u64);

#[derive(Clone)]
pub struct MetricsRegistry {
    registry: Arc<Mutex<Registry>>,
    // counters (delta-applied)
    interface_rx_bytes: Family<InterfaceLabels, Counter>,
    interface_tx_bytes: Family<InterfaceLabels, Counter>,
    interface_rx_packets: Family<InterfaceLabels, Counter>,
    interface_tx_packets: Family<InterfaceLabels, Counter>,
    interface_rx_errors: Family<InterfaceLabels, Counter>,
    interface_tx_errors: Family<InterfaceLabels, Counter>,
    // gauges
    interface_running: Family<InterfaceLabels, Gauge>,
    system_cpu_load: Family<RouterLabels, Gauge>,
    system_free_memory: Family<RouterLabels, Gauge>,
    system_total_memory: Family<RouterLabels, Gauge>,
    system_info: Family<SystemInfoLabels, Gauge>,
    system_uptime_seconds: Family<RouterLabels, Gauge>,
    // scrape status counters
    scrape_success: Family<RouterLabels, Counter>,
    scrape_errors: Family<RouterLabels, Counter>,
    // previous snapshot for counters
    prev_iface: Arc<Mutex<std::collections::HashMap<InterfaceLabels, InterfaceSnapshot>>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let interface_rx_bytes = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_rx_bytes",
            "Received bytes on interface",
            interface_rx_bytes.clone(),
        );
        let interface_tx_bytes = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_tx_bytes",
            "Transmitted bytes on interface",
            interface_tx_bytes.clone(),
        );
        let interface_rx_packets = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_rx_packets",
            "Received packets on interface",
            interface_rx_packets.clone(),
        );
        let interface_tx_packets = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_tx_packets",
            "Transmitted packets on interface",
            interface_tx_packets.clone(),
        );
        let interface_rx_errors = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_rx_errors",
            "Receive errors on interface",
            interface_rx_errors.clone(),
        );
        let interface_tx_errors = Family::<InterfaceLabels, Counter>::default();
        registry.register(
            "mikrotik_interface_tx_errors",
            "Transmit errors on interface",
            interface_tx_errors.clone(),
        );
        let interface_running = Family::<InterfaceLabels, Gauge>::default();
        registry.register(
            "mikrotik_interface_running",
            "Interface running status (1=running,0=down)",
            interface_running.clone(),
        );

        let system_cpu_load = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_cpu_load",
            "CPU load percentage",
            system_cpu_load.clone(),
        );
        let system_free_memory = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_free_memory_bytes",
            "Free memory bytes",
            system_free_memory.clone(),
        );
        let system_total_memory = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_total_memory_bytes",
            "Total memory bytes",
            system_total_memory.clone(),
        );
        let system_info = Family::<SystemInfoLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_info",
            "Static system info (value=1)",
            system_info.clone(),
        );
        let system_uptime_seconds = Family::<RouterLabels, Gauge>::default();
        registry.register(
            "mikrotik_system_uptime_seconds",
            "System uptime in seconds",
            system_uptime_seconds.clone(),
        );
        let scrape_success = Family::<RouterLabels, Counter>::default();
        registry.register(
            "mikrotik_scrape_success",
            "Successful scrape cycles per router",
            scrape_success.clone(),
        );
        let scrape_errors = Family::<RouterLabels, Counter>::default();
        registry.register(
            "mikrotik_scrape_errors",
            "Failed scrape cycles per router",
            scrape_errors.clone(),
        );

        Self {
            registry: Arc::new(Mutex::new(registry)),
            interface_rx_bytes,
            interface_tx_bytes,
            interface_rx_packets,
            interface_tx_packets,
            interface_rx_errors,
            interface_tx_errors,
            interface_running,
            system_cpu_load,
            system_free_memory,
            system_total_memory,
            system_info,
            system_uptime_seconds,
            scrape_success,
            scrape_errors,
            prev_iface: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub async fn update_metrics(&self, metrics: &RouterMetrics) {
        {
            let mut prev = self.prev_iface.lock().await;
            for iface in &metrics.interfaces {
                let labels = InterfaceLabels {
                    router: metrics.router_name.clone(),
                    interface: iface.name.clone(),
                };
                let (prx, ptx, prxp, ptxp, prxe, ptxe) = prev.get(&labels).cloned().unwrap_or((
                    iface.rx_bytes,
                    iface.tx_bytes,
                    iface.rx_packets,
                    iface.tx_packets,
                    iface.rx_errors,
                    iface.tx_errors,
                ));
                // compute deltas (handle reset)
                let dx_rx_bytes = iface.rx_bytes.saturating_sub(prx);
                let dx_tx_bytes = iface.tx_bytes.saturating_sub(ptx);
                let dx_rx_packets = iface.rx_packets.saturating_sub(prxp);
                let dx_tx_packets = iface.tx_packets.saturating_sub(ptxp);
                let dx_rx_errors = iface.rx_errors.saturating_sub(prxe);
                let dx_tx_errors = iface.tx_errors.saturating_sub(ptxe);
                self.interface_rx_bytes
                    .get_or_create(&labels)
                    .inc_by(dx_rx_bytes);
                self.interface_tx_bytes
                    .get_or_create(&labels)
                    .inc_by(dx_tx_bytes);
                self.interface_rx_packets
                    .get_or_create(&labels)
                    .inc_by(dx_rx_packets);
                self.interface_tx_packets
                    .get_or_create(&labels)
                    .inc_by(dx_tx_packets);
                self.interface_rx_errors
                    .get_or_create(&labels)
                    .inc_by(dx_rx_errors);
                self.interface_tx_errors
                    .get_or_create(&labels)
                    .inc_by(dx_tx_errors);
                self.interface_running
                    .get_or_create(&labels)
                    .set(if iface.running { 1 } else { 0 });
                prev.insert(
                    labels,
                    (
                        iface.rx_bytes,
                        iface.tx_bytes,
                        iface.rx_packets,
                        iface.tx_packets,
                        iface.rx_errors,
                        iface.tx_errors,
                    ),
                );
            }
        }

        let router_label = RouterLabels {
            router: metrics.router_name.clone(),
        };
        self.system_cpu_load
            .get_or_create(&router_label)
            .set(metrics.system.cpu_load as i64);
        self.system_free_memory
            .get_or_create(&router_label)
            .set(metrics.system.free_memory as i64);
        self.system_total_memory
            .get_or_create(&router_label)
            .set(metrics.system.total_memory as i64);
        // parse uptime string to seconds
        let uptime_secs = parse_uptime_to_seconds(&metrics.system.uptime);
        self.system_uptime_seconds
            .get_or_create(&router_label)
            .set(uptime_secs as i64);
        let info_labels = SystemInfoLabels {
            router: metrics.router_name.clone(),
            version: metrics.system.version.clone(),
            board: metrics.system.board_name.clone(),
        };
        self.system_info.get_or_create(&info_labels).set(1);
    }

    pub async fn encode_metrics(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let registry = self.registry.lock().await;
        let mut buffer = String::new();
        encode(&mut buffer, &registry)?;
        Ok(buffer)
    }

    pub fn record_scrape_success(&self, labels: &RouterLabels) {
        self.scrape_success.get_or_create(labels).inc();
    }

    pub fn record_scrape_error(&self, labels: &RouterLabels) {
        self.scrape_errors.get_or_create(labels).inc();
    }
}

fn parse_uptime_to_seconds(s: &str) -> u64 {
    // Accept formats like 1d2h3m4s, 2w1d, 05:23:10, 1h5m, 30s
    if s.contains(':') {
        // HH:MM:SS or MM:SS
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 3 {
            let h = parts[0].parse::<u64>().unwrap_or(0);
            let m = parts[1].parse::<u64>().unwrap_or(0);
            let sec = parts[2].parse::<u64>().unwrap_or(0);
            return h * 3600 + m * 60 + sec;
        } else if parts.len() == 2 {
            let m = parts[0].parse::<u64>().unwrap_or(0);
            let sec = parts[1].parse::<u64>().unwrap_or(0);
            return m * 60 + sec;
        }
    }
    let mut total = 0u64;
    let mut num = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num.push(ch);
            continue;
        }
        if num.is_empty() {
            continue;
        }
        let value = num.parse::<u64>().unwrap_or(0);
        let unit_seconds = match ch {
            'w' => 7 * 24 * 3600,
            'd' => 24 * 3600,
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => 0,
        };
        total += value * unit_seconds;
        num.clear();
    }
    if !num.is_empty() {
        // trailing number without unit -> seconds
        total += num.parse::<u64>().unwrap_or(0);
    }
    total
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}
