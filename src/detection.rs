use std::{collections::HashMap, net::IpAddr};

use crate::{
    config::DetectionConfig,
    models::{NormalizedPacket, SecurityAlert, Severity, TransportProtocol},
};

const MAX_TARGETS_PER_TRACKER: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Target {
    Port(u16),
    Host(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ScanKey {
    Vertical {
        source: IpAddr,
        destination: IpAddr,
    },
    Horizontal {
        source: IpAddr,
        destination_port: u16,
    },
}

#[derive(Debug, Default)]
struct Tracker {
    targets: HashMap<Target, u128>,
    last_updated_ns: u128,
    alerted: bool,
}

/// Bounded vertical and horizontal TCP/UDP scan heuristics for offline captures.
pub struct PortScanDetector {
    vertical_threshold: usize,
    horizontal_threshold: usize,
    window_ns: u128,
    max_trackers: usize,
    watermark_ns: Option<u128>,
    vertical: HashMap<ScanKey, Tracker>,
    horizontal: HashMap<ScanKey, Tracker>,
}

impl PortScanDetector {
    pub fn new(config: &DetectionConfig, max_trackers: usize) -> Self {
        Self {
            vertical_threshold: config.port_scan_unique_ports,
            horizontal_threshold: config.horizontal_scan_unique_hosts,
            window_ns: (config.scan_window_secs as u128).saturating_mul(1_000_000_000),
            max_trackers: max_trackers.max(1),
            watermark_ns: None,
            vertical: HashMap::new(),
            horizontal: HashMap::new(),
        }
    }

    pub fn active_tracker_count(&self) -> usize {
        self.vertical.len() + self.horizontal.len()
    }

    pub fn observe(&mut self, packet: &NormalizedPacket) -> Vec<SecurityAlert> {
        if !matches!(
            packet.protocol,
            TransportProtocol::Tcp | TransportProtocol::Udp
        ) {
            return Vec::new();
        }
        let (Some(_source_port), Some(destination_port)) =
            (packet.source_port, packet.destination_port)
        else {
            return Vec::new();
        };
        let watermark = self
            .watermark_ns
            .map_or(packet.timestamp_ns, |old| old.max(packet.timestamp_ns));
        self.watermark_ns = Some(watermark);
        if watermark.saturating_sub(packet.timestamp_ns) >= self.window_ns {
            return Vec::new();
        }

        let vertical_key = ScanKey::Vertical {
            source: packet.source_ip,
            destination: packet.destination_ip,
        };
        let horizontal_key = ScanKey::Horizontal {
            source: packet.source_ip,
            destination_port,
        };
        let mut alerts = Vec::with_capacity(2);
        if let Some(alert) = self.observe_vertical(vertical_key, destination_port, packet) {
            alerts.push(alert);
        }
        if let Some(alert) = self.observe_horizontal(horizontal_key, packet.destination_ip, packet)
        {
            alerts.push(alert);
        }
        alerts
    }

    fn observe_vertical(
        &mut self,
        key: ScanKey,
        port: u16,
        packet: &NormalizedPacket,
    ) -> Option<SecurityAlert> {
        if !self.vertical.contains_key(&key) {
            self.ensure_capacity();
            self.vertical.insert(key.clone(), Tracker::default());
        }
        let tracker = self.vertical.get_mut(&key)?;
        let watermark = self.watermark_ns.unwrap_or(packet.timestamp_ns);
        tracker
            .targets
            .retain(|_, seen| watermark.saturating_sub(*seen) < self.window_ns);
        tracker.last_updated_ns = tracker.last_updated_ns.max(packet.timestamp_ns);
        if tracker.targets.len() < MAX_TARGETS_PER_TRACKER {
            tracker
                .targets
                .entry(Target::Port(port))
                .or_insert(packet.timestamp_ns);
        }
        if tracker.targets.is_empty() {
            tracker.alerted = false;
        }
        if tracker.alerted || tracker.targets.len() < self.vertical_threshold {
            return None;
        }
        tracker.alerted = true;
        let mut ports: Vec<u16> = tracker
            .targets
            .keys()
            .filter_map(|t| match t {
                Target::Port(p) => Some(*p),
                _ => None,
            })
            .collect();
        ports.sort_unstable();
        let sample = ports.iter().take(12).map(u16::to_string).collect::<Vec<_>>().join(", ");
        let (source, destination) = match key { ScanKey::Vertical { source, destination } => (source, destination), _ => return None };
        Some(SecurityAlert {
            rule_id: "PORT_SCAN_VERTICAL".into(),
            title: "Potential vertical port scan".into(),
            severity: Severity::High,
            source_ip: Some(source),
            destination_ip: Some(destination),
            confidence: 0.75,
            evidence: vec![
                format!(
                    "Observed {} unique destination ports; threshold is {}.",
                    tracker.targets.len(),
                    self.vertical_threshold
                ),
                format!(
                    "Observation window: {} seconds.",
                    self.window_ns / 1_000_000_000
                ),
                format!("Destination port sample: {sample}."),
                "Legitimate service discovery can produce similar traffic; review this indicator.".into(),
            ],
        })
    }

    fn observe_horizontal(
        &mut self,
        key: ScanKey,
        host: IpAddr,
        packet: &NormalizedPacket,
    ) -> Option<SecurityAlert> {
        if !self.horizontal.contains_key(&key) {
            self.ensure_capacity();
            self.horizontal.insert(key.clone(), Tracker::default());
        }
        let tracker = self.horizontal.get_mut(&key)?;
        let watermark = self.watermark_ns.unwrap_or(packet.timestamp_ns);
        tracker
            .targets
            .retain(|_, seen| watermark.saturating_sub(*seen) < self.window_ns);
        tracker.last_updated_ns = tracker.last_updated_ns.max(packet.timestamp_ns);
        if tracker.targets.len() < MAX_TARGETS_PER_TRACKER {
            tracker
                .targets
                .entry(Target::Host(host))
                .or_insert(packet.timestamp_ns);
        }
        if tracker.targets.is_empty() {
            tracker.alerted = false;
        }
        if tracker.alerted || tracker.targets.len() < self.horizontal_threshold {
            return None;
        }
        tracker.alerted = true;
        let mut hosts: Vec<IpAddr> = tracker
            .targets
            .keys()
            .filter_map(|t| match t {
                Target::Host(ip) => Some(*ip),
                _ => None,
            })
            .collect();
        hosts.sort_unstable();
        let sample = hosts.iter().take(12).map(ToString::to_string).collect::<Vec<_>>().join(", ");
        let (source, destination_port) = match key { ScanKey::Horizontal { source, destination_port } => (source, destination_port), _ => return None };
        Some(SecurityAlert {
            rule_id: "PORT_SCAN_HORIZONTAL".into(),
            title: "Potential horizontal port scan".into(),
            severity: Severity::High,
            source_ip: Some(source),
            destination_ip: None,
            confidence: 0.75,
            evidence: vec![
                format!(
                    "Observed {} unique destination hosts on port {destination_port}; threshold is {}.",
                    tracker.targets.len(),
                    self.horizontal_threshold
                ),
                format!("Observation window: {} seconds.", self.window_ns / 1_000_000_000),
                format!("Destination host sample: {sample}."),
                "Legitimate inventory and monitoring can produce similar traffic; review this indicator.".into(),
            ],
        })
    }

    fn ensure_capacity(&mut self) {
        if self.active_tracker_count() < self.max_trackers {
            return;
        }
        let oldest_vertical = self
            .vertical
            .iter()
            .min_by_key(|(_, t)| t.last_updated_ns)
            .map(|(k, t)| (t.last_updated_ns, k.clone()));
        let oldest_horizontal = self
            .horizontal
            .iter()
            .min_by_key(|(_, t)| t.last_updated_ns)
            .map(|(k, t)| (t.last_updated_ns, k.clone()));
        match (oldest_vertical, oldest_horizontal) {
            (Some((vt, vk)), Some((ht, hk))) if vt <= ht => { self.vertical.remove(&vk); }
            (Some(_), Some((_, hk))) => { self.horizontal.remove(&hk); }
            (Some((_, vk)), None) => { self.vertical.remove(&vk); }
            (None, Some((_, hk))) => { self.horizontal.remove(&hk); }
            (None, None) => {}
        }
    }
}
