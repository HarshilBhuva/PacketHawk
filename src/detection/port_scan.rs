use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    config::DetectionConfig,
    models::{NormalizedPacket, SecurityAlert, Severity, TransportProtocol},
};

/// Statistics for a single port-scan evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortScanStats {
    pub packets_considered: usize,
    pub vertical_alerts: usize,
    pub horizontal_alerts: usize,
}

/// Results from the vertical and horizontal TCP/UDP scan heuristics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortScanReport {
    pub stats: PortScanStats,
    pub alerts: Vec<SecurityAlert>,
}

/// Detects vertical and horizontal scans using bounded-duration packet windows.
///
/// Input is grouped by source and sorted by capture timestamp. The sliding
/// window maintains reference counts, so removing old packets does not
/// accidentally remove a destination that is still represented in the window.
pub struct PortScanDetector {
    config: DetectionConfig,
}

impl PortScanDetector {
    pub fn new(config: DetectionConfig) -> Self {
        Self { config }
    }

    pub fn analyze(&self, packets: &[NormalizedPacket]) -> PortScanReport {
        let mut by_source: HashMap<_, Vec<&NormalizedPacket>> = HashMap::new();
        let mut considered = 0usize;

        for packet in packets {
            if packet.destination_port.is_some()
                && matches!(packet.protocol, TransportProtocol::Tcp | TransportProtocol::Udp)
            {
                by_source.entry(packet.source_ip).or_default().push(packet);
                considered = considered.saturating_add(1);
            }
        }

        let mut alerts = Vec::new();
        for (source_ip, mut source_packets) in by_source {
            source_packets.sort_by_key(|packet| packet.timestamp_ns);
            self.analyze_source(source_ip, &source_packets, &mut alerts);
        }

        alerts.sort_by(|left, right| {
            left.rule_id
                .cmp(&right.rule_id)
                .then_with(|| left.source_ip.cmp(&right.source_ip))
                .then_with(|| left.destination_ip.cmp(&right.destination_ip))
                .then_with(|| left.title.cmp(&right.title))
        });

        let vertical_alerts = alerts
            .iter()
            .filter(|alert| alert.rule_id == "PORT_SCAN_VERTICAL")
            .count();
        let horizontal_alerts = alerts
            .iter()
            .filter(|alert| alert.rule_id == "PORT_SCAN_HORIZONTAL")
            .count();

        PortScanReport {
            stats: PortScanStats {
                packets_considered: considered,
                vertical_alerts,
                horizontal_alerts,
            },
            alerts,
        }
    }

    fn analyze_source(
        &self,
        source_ip: std::net::IpAddr,
        packets: &[&NormalizedPacket],
        alerts: &mut Vec<SecurityAlert>,
    ) {
        let window_ns = (self.config.scan_window_secs as u128).saturating_mul(1_000_000_000);
        let mut vertical: HashMap<std::net::IpAddr, HashMap<u16, usize>> = HashMap::new();
        let mut horizontal: HashMap<u16, HashMap<std::net::IpAddr, usize>> = HashMap::new();
        let mut emitted_vertical = HashSet::new();
        let mut emitted_horizontal = HashSet::new();
        let mut left = 0usize;

        for right in 0..packets.len() {
            let packet = packets[right];
            let destination = packet.destination_ip;
            let port = packet.destination_port.expect("filtered port-bearing packets");
            *vertical.entry(destination).or_default().entry(port).or_default() += 1;
            *horizontal.entry(port).or_default().entry(destination).or_default() += 1;

            while packet.timestamp_ns.saturating_sub(packets[left].timestamp_ns) > window_ns {
                let expired = packets[left];
                let expired_destination = expired.destination_ip;
                let expired_port = expired.destination_port.expect("filtered port-bearing packets");
                decrement(&mut vertical, &expired_destination, &expired_port);
                decrement(&mut horizontal, &expired_port, &expired_destination);
                left += 1;
            }

            if let Some(ports) = vertical.get(&destination) {
                if ports.len() >= self.config.port_scan_unique_ports
                    && emitted_vertical.insert(destination)
                {
                    let observed: BTreeSet<_> = ports.keys().copied().collect();
                    let severity = if observed.len()
                        >= self.config.port_scan_unique_ports.saturating_mul(2)
                    {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    alerts.push(SecurityAlert {
                        rule_id: "PORT_SCAN_VERTICAL".into(),
                        title: format!("Vertical port scan against {destination}"),
                        severity,
                        source_ip: Some(source_ip),
                        destination_ip: Some(destination),
                        confidence: confidence(observed.len(), self.config.port_scan_unique_ports),
                        evidence: vec![
                            format!("Observed {} unique destination ports", observed.len()),
                            format!("Destination ports: {}", join_ports(&observed)),
                            format!("Window: {} seconds", self.config.scan_window_secs),
                            format!("Configured threshold: {} unique ports", self.config.port_scan_unique_ports),
                            format!("Capture window: {}..={} ns", packets[left].timestamp_ns, packet.timestamp_ns),
                        ],
                    });
                }
            }

            if let Some(hosts) = horizontal.get(&port) {
                if hosts.len() >= self.config.horizontal_scan_unique_hosts
                    && emitted_horizontal.insert(port)
                {
                    let observed: BTreeSet<_> = hosts.keys().copied().collect();
                    let severity = if observed.len()
                        >= self.config.horizontal_scan_unique_hosts.saturating_mul(2)
                    {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    alerts.push(SecurityAlert {
                        rule_id: "PORT_SCAN_HORIZONTAL".into(),
                        title: format!("Horizontal scan of destination port {port}"),
                        severity,
                        source_ip: Some(source_ip),
                        destination_ip: None,
                        confidence: confidence(observed.len(), self.config.horizontal_scan_unique_hosts),
                        evidence: vec![
                            format!("Observed {} unique destination hosts", observed.len()),
                            format!("Destination port: {port}"),
                            format!("Destination hosts: {}", join_hosts(&observed)),
                            format!("Window: {} seconds", self.config.scan_window_secs),
                            format!("Configured threshold: {} unique hosts", self.config.horizontal_scan_unique_hosts),
                            format!("Capture window: {}..={} ns", packets[left].timestamp_ns, packet.timestamp_ns),
                        ],
                    });
                }
            }
        }
    }
}

fn decrement<K1, K2>(map: &mut HashMap<K1, HashMap<K2, usize>>, outer: &K1, inner: &K2)
where
    K1: std::hash::Hash + Eq,
    K2: std::hash::Hash + Eq,
{
    if let Some(counts) = map.get_mut(outer) {
        if let Some(count) = counts.get_mut(inner) {
            *count -= 1;
            if *count == 0 {
                counts.remove(inner);
            }
        }
        if counts.is_empty() {
            map.remove(outer);
        }
    }
}

fn confidence(observed: usize, threshold: usize) -> f32 {
    (0.55 + (observed.saturating_sub(threshold) as f32 / threshold.max(1) as f32) * 0.4)
        .clamp(0.55, 0.95)
}

fn join_ports(ports: &BTreeSet<u16>) -> String {
    ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
}

fn join_hosts(hosts: &BTreeSet<std::net::IpAddr>) -> String {
    hosts.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}
