//! Bounded, incremental detection state for timestamp-ordered capture streams.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
};

use crate::{
    config::DetectionConfig,
    models::{NormalizedPacket, SecurityAlert, Severity, TransportProtocol},
};

use super::{
    DetectionReport,
    beacon::{BeaconReport, BeaconStats},
    dns_anomaly::{DnsAnomalyReport, DnsAnomalyStats},
    port_scan::{PortScanReport, PortScanStats},
};

const MAX_SCAN_SOURCES: usize = 8_192;
const MAX_SCAN_EVENTS_TOTAL: usize = 250_000;
const MAX_SCAN_EVENTS_PER_SOURCE: usize = 4_096;
const MAX_EMITTED_SCAN_KEYS_PER_SOURCE: usize = 4_096;
const MAX_BEACON_CONVERSATIONS: usize = 100_000;
const MAX_DNS_DEDUP_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DetectionStreamStats {
    pub packets_seen: usize,
    pub late_packets_ignored: usize,
    pub state_evictions: usize,
}

#[derive(Debug, Clone, Copy)]
struct ScanEvent {
    timestamp_ns: u128,
    destination: IpAddr,
    destination_port: u16,
}

#[derive(Debug, Default)]
struct ScanSourceState {
    events: VecDeque<ScanEvent>,
    vertical: HashMap<IpAddr, HashMap<u16, usize>>,
    horizontal: HashMap<u16, HashMap<IpAddr, usize>>,
    emitted_vertical: HashSet<IpAddr>,
    emitted_horizontal: HashSet<u16>,
    last_updated_ns: u128,
}

struct PortScanStream {
    config: DetectionConfig,
    window_ns: u128,
    sources: HashMap<IpAddr, ScanSourceState>,
    active_events: usize,
    stats: PortScanStats,
    alerts: Vec<SecurityAlert>,
}

impl PortScanStream {
    fn new(config: DetectionConfig) -> Self {
        Self {
            window_ns: (config.scan_window_secs as u128).saturating_mul(1_000_000_000),
            config,
            sources: HashMap::new(),
            active_events: 0,
            stats: PortScanStats::default(),
            alerts: Vec::new(),
        }
    }

    fn observe(&mut self, packet: &NormalizedPacket) {
        if !matches!(
            packet.protocol,
            TransportProtocol::Tcp | TransportProtocol::Udp
        ) {
            return;
        }
        let Some(port) = packet.destination_port else {
            return;
        };
        self.stats.packets_considered = self.stats.packets_considered.saturating_add(1);
        let source = packet.source_ip;

        if !self.sources.contains_key(&source) && self.sources.len() >= MAX_SCAN_SOURCES {
            self.evict_oldest_source(None);
        }
        self.sources.entry(source).or_default();

        self.expire_source(source, packet.timestamp_ns);

        let reset_required = self.sources.get(&source).is_some_and(|state| {
            state.events.len() >= MAX_SCAN_EVENTS_PER_SOURCE
                || state.emitted_vertical.len() >= MAX_EMITTED_SCAN_KEYS_PER_SOURCE
                || state.emitted_horizontal.len() >= MAX_EMITTED_SCAN_KEYS_PER_SOURCE
        });
        if reset_required {
            self.reset_source(source);
        }

        if self.active_events >= MAX_SCAN_EVENTS_TOTAL {
            self.evict_oldest_source(Some(source));
            if self.active_events >= MAX_SCAN_EVENTS_TOTAL {
                self.reset_source(source);
            }
        }

        let state = self.sources.entry(source).or_default();
        let event = ScanEvent {
            timestamp_ns: packet.timestamp_ns,
            destination: packet.destination_ip,
            destination_port: port,
        };
        state.events.push_back(event);
        state.last_updated_ns = packet.timestamp_ns;
        *state
            .vertical
            .entry(event.destination)
            .or_default()
            .entry(port)
            .or_default() += 1;
        *state
            .horizontal
            .entry(port)
            .or_default()
            .entry(event.destination)
            .or_default() += 1;
        self.active_events = self.active_events.saturating_add(1);

        if let Some(ports) = state.vertical.get(&event.destination) {
            if ports.len() >= self.config.port_scan_unique_ports
                && state.emitted_vertical.insert(event.destination)
            {
                let observed: std::collections::BTreeSet<_> = ports.keys().copied().collect();
                let severity =
                    if observed.len() >= self.config.port_scan_unique_ports.saturating_mul(2) {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                let first_seen = state
                    .events
                    .front()
                    .map_or(packet.timestamp_ns, |item| item.timestamp_ns);
                self.alerts.push(SecurityAlert {
                    rule_id: "PORT_SCAN_VERTICAL".into(),
                    title: format!("Vertical port scan against {}", event.destination),
                    severity,
                    source_ip: Some(source),
                    destination_ip: Some(event.destination),
                    confidence: confidence(observed.len(), self.config.port_scan_unique_ports),
                    evidence: vec![
                        format!("Observed {} unique destination ports", observed.len()),
                        format!("Destination ports: {}", join_ports(&observed)),
                        format!("Window: {} seconds", self.config.scan_window_secs),
                        format!(
                            "Configured threshold: {} unique ports",
                            self.config.port_scan_unique_ports
                        ),
                        format!("Capture window: {first_seen}..={} ns", packet.timestamp_ns),
                    ],
                });
            }
        }

        if let Some(hosts) = state.horizontal.get(&port) {
            if hosts.len() >= self.config.horizontal_scan_unique_hosts
                && state.emitted_horizontal.insert(port)
            {
                let observed: std::collections::BTreeSet<_> = hosts.keys().copied().collect();
                let severity = if observed.len()
                    >= self.config.horizontal_scan_unique_hosts.saturating_mul(2)
                {
                    Severity::High
                } else {
                    Severity::Medium
                };
                let first_seen = state
                    .events
                    .front()
                    .map_or(packet.timestamp_ns, |item| item.timestamp_ns);
                self.alerts.push(SecurityAlert {
                    rule_id: "PORT_SCAN_HORIZONTAL".into(),
                    title: format!("Horizontal scan of destination port {port}"),
                    severity,
                    source_ip: Some(source),
                    destination_ip: None,
                    confidence: confidence(
                        observed.len(),
                        self.config.horizontal_scan_unique_hosts,
                    ),
                    evidence: vec![
                        format!("Observed {} unique destination hosts", observed.len()),
                        format!("Destination port: {port}"),
                        format!("Destination hosts: {}", join_hosts(&observed)),
                        format!("Window: {} seconds", self.config.scan_window_secs),
                        format!(
                            "Configured threshold: {} unique hosts",
                            self.config.horizontal_scan_unique_hosts
                        ),
                        format!("Capture window: {first_seen}..={} ns", packet.timestamp_ns),
                    ],
                });
            }
        }
    }

    fn expire_source(&mut self, source: IpAddr, watermark_ns: u128) {
        let mut expired_count = 0usize;
        if let Some(state) = self.sources.get_mut(&source) {
            while state.events.front().is_some_and(|event| {
                watermark_ns.saturating_sub(event.timestamp_ns) > self.window_ns
            }) {
                if let Some(event) = state.events.pop_front() {
                    decrement(
                        &mut state.vertical,
                        &event.destination,
                        &event.destination_port,
                    );
                    decrement(
                        &mut state.horizontal,
                        &event.destination_port,
                        &event.destination,
                    );
                    expired_count += 1;
                }
            }
        }
        self.active_events = self.active_events.saturating_sub(expired_count);
    }

    fn reset_source(&mut self, source: IpAddr) {
        if let Some(state) = self.sources.remove(&source) {
            self.active_events = self.active_events.saturating_sub(state.events.len());
            self.stats.state_evictions = self.stats.state_evictions.saturating_add(1);
        }
        self.sources.insert(source, ScanSourceState::default());
    }

    fn evict_oldest_source(&mut self, except: Option<IpAddr>) {
        let candidate = self
            .sources
            .iter()
            .filter(|(source, _)| Some(**source) != except)
            .min_by_key(|(_, state)| state.last_updated_ns)
            .map(|(source, _)| *source);
        let candidate = candidate.or(except);
        if let Some(source) = candidate {
            if let Some(state) = self.sources.remove(&source) {
                self.active_events = self.active_events.saturating_sub(state.events.len());
                self.stats.state_evictions = self.stats.state_evictions.saturating_add(1);
            }
        }
    }

    fn finish(mut self) -> PortScanReport {
        self.alerts.sort_by(|left, right| {
            left.rule_id
                .cmp(&right.rule_id)
                .then_with(|| left.source_ip.cmp(&right.source_ip))
                .then_with(|| left.destination_ip.cmp(&right.destination_ip))
                .then_with(|| left.title.cmp(&right.title))
        });
        self.stats.vertical_alerts = self
            .alerts
            .iter()
            .filter(|alert| alert.rule_id == "PORT_SCAN_VERTICAL")
            .count();
        self.stats.horizontal_alerts = self
            .alerts
            .iter()
            .filter(|alert| alert.rule_id == "PORT_SCAN_HORIZONTAL")
            .count();
        PortScanReport {
            stats: self.stats,
            alerts: self.alerts,
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
            *count = count.saturating_sub(1);
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

fn join_ports(ports: &std::collections::BTreeSet<u16>) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_hosts(hosts: &std::collections::BTreeSet<IpAddr>) -> String {
    hosts
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConversationKey {
    source: IpAddr,
    destination: IpAddr,
    destination_port: u16,
    protocol: TransportProtocol,
}

#[derive(Debug, Clone, Default)]
struct BeaconState {
    first_seen_ns: u128,
    last_seen_ns: u128,
    last_updated_ns: u128,
    packet_count: usize,
    interval_count: usize,
    zero_intervals: usize,
    mean_interval: f64,
    squared_deviation_sum: f64,
}

struct BeaconStream {
    config: DetectionConfig,
    conversations: HashMap<ConversationKey, BeaconState>,
    conversations_seen: usize,
    state_evictions: usize,
}

impl BeaconStream {
    fn new(config: DetectionConfig) -> Self {
        Self {
            config,
            conversations: HashMap::new(),
            conversations_seen: 0,
            state_evictions: 0,
        }
    }

    fn observe(&mut self, packet: &NormalizedPacket) {
        if !matches!(
            packet.protocol,
            TransportProtocol::Tcp | TransportProtocol::Udp
        ) {
            return;
        }
        let Some(destination_port) = packet.destination_port else {
            return;
        };
        let key = ConversationKey {
            source: packet.source_ip,
            destination: packet.destination_ip,
            destination_port,
            protocol: packet.protocol,
        };
        if !self.conversations.contains_key(&key) {
            if self.conversations.len() >= MAX_BEACON_CONVERSATIONS {
                if let Some(oldest) = self
                    .conversations
                    .iter()
                    .min_by_key(|(_, state)| state.last_updated_ns)
                    .map(|(key, _)| *key)
                {
                    self.conversations.remove(&oldest);
                    self.state_evictions = self.state_evictions.saturating_add(1);
                }
            }
            self.conversations_seen = self.conversations_seen.saturating_add(1);
            self.conversations.insert(
                key,
                BeaconState {
                    first_seen_ns: packet.timestamp_ns,
                    last_seen_ns: packet.timestamp_ns,
                    last_updated_ns: packet.timestamp_ns,
                    packet_count: 1,
                    ..BeaconState::default()
                },
            );
            return;
        }

        if let Some(state) = self.conversations.get_mut(&key) {
            let interval = packet.timestamp_ns.saturating_sub(state.last_seen_ns);
            if interval == 0 {
                state.zero_intervals = state.zero_intervals.saturating_add(1);
            } else {
                state.interval_count = state.interval_count.saturating_add(1);
                let value = interval as f64;
                let delta = value - state.mean_interval;
                state.mean_interval += delta / state.interval_count as f64;
                let delta_after = value - state.mean_interval;
                state.squared_deviation_sum += delta * delta_after;
            }
            state.packet_count = state.packet_count.saturating_add(1);
            state.last_seen_ns = packet.timestamp_ns;
            state.last_updated_ns = packet.timestamp_ns;
        }
    }

    fn finish(self) -> BeaconReport {
        let mut alerts = Vec::new();
        for (key, state) in self.conversations {
            if state.packet_count < self.config.beacon_min_samples
                || state.zero_intervals > 0
                || state.interval_count == 0
                || state.mean_interval <= 0.0
            {
                continue;
            }
            let variance = state.squared_deviation_sum / state.interval_count as f64;
            let standard_deviation = variance.sqrt();
            let coefficient_of_variation = standard_deviation / state.mean_interval;
            if coefficient_of_variation > self.config.beacon_max_interval_cv {
                continue;
            }
            let severity = if coefficient_of_variation <= self.config.beacon_max_interval_cv * 0.5 {
                Severity::High
            } else {
                Severity::Medium
            };
            let confidence = (0.6
                + (self.config.beacon_max_interval_cv - coefficient_of_variation)
                    / self.config.beacon_max_interval_cv.max(f64::EPSILON)
                    * 0.3)
                .clamp(0.6, 0.95) as f32;
            alerts.push(SecurityAlert {
                rule_id: "NETWORK_BEACONING".into(),
                title: format!(
                    "Regular periodic traffic to {}:{}",
                    key.destination, key.destination_port
                ),
                severity,
                source_ip: Some(key.source),
                destination_ip: Some(key.destination),
                confidence,
                evidence: vec![
                    format!("Observed {} packets", state.packet_count),
                    format!("Mean interval: {:.3} ms", state.mean_interval / 1_000_000.0),
                    format!(
                        "Interval standard deviation: {:.3} ms",
                        standard_deviation / 1_000_000.0
                    ),
                    format!("Interval coefficient of variation: {coefficient_of_variation:.4}"),
                    format!(
                        "Configured maximum interval CV: {:.4}",
                        self.config.beacon_max_interval_cv
                    ),
                    format!(
                        "Capture window: {}..={} ns",
                        state.first_seen_ns, state.last_seen_ns
                    ),
                    format!("Transport: {:?}", key.protocol),
                ],
            });
        }
        alerts.sort_by(|left, right| {
            left.source_ip
                .cmp(&right.source_ip)
                .then_with(|| left.destination_ip.cmp(&right.destination_ip))
                .then_with(|| left.title.cmp(&right.title))
        });
        BeaconReport {
            stats: BeaconStats {
                conversations_considered: self.conversations_seen,
                alerts: alerts.len(),
                state_evictions: self.state_evictions,
            },
            alerts,
        }
    }
}

struct DnsStream {
    max_query_length: usize,
    entropy_threshold: f64,
    seen: HashSet<(IpAddr, String)>,
    order: VecDeque<(IpAddr, String)>,
    queries_inspected: usize,
    state_evictions: usize,
    alerts: Vec<SecurityAlert>,
}

impl DnsStream {
    fn new(config: DetectionConfig) -> Self {
        Self {
            max_query_length: config.dns_max_query_length,
            entropy_threshold: config.dns_entropy_threshold,
            seen: HashSet::new(),
            order: VecDeque::new(),
            queries_inspected: 0,
            state_evictions: 0,
            alerts: Vec::new(),
        }
    }

    fn observe(&mut self, packet: &NormalizedPacket) {
        let Some(query) = packet.dns_query_name.as_deref() else {
            return;
        };
        self.queries_inspected = self.queries_inspected.saturating_add(1);
        let key = (packet.source_ip, query.to_ascii_lowercase());
        if self.seen.contains(&key) {
            return;
        }
        if self.order.len() >= MAX_DNS_DEDUP_ENTRIES {
            if let Some(expired) = self.order.pop_front() {
                self.seen.remove(&expired);
                self.state_evictions = self.state_evictions.saturating_add(1);
            }
        }
        self.seen.insert(key.clone());
        self.order.push_back(key);

        let length = query.len();
        let entropy = shannon_entropy(query.as_bytes());
        let is_long = length > self.max_query_length;
        let is_high_entropy = entropy >= self.entropy_threshold;
        if !is_long && !is_high_entropy {
            return;
        }
        let severity = if length > self.max_query_length.saturating_mul(2)
            || entropy >= self.entropy_threshold + 1.0
        {
            Severity::High
        } else {
            Severity::Medium
        };
        let confidence = if is_long && is_high_entropy {
            0.85
        } else {
            0.7
        };
        self.alerts.push(SecurityAlert {
            rule_id: "DNS_QUERY_ANOMALY".into(),
            title: "Unusual DNS query name".into(),
            severity,
            source_ip: Some(packet.source_ip),
            destination_ip: Some(packet.destination_ip),
            confidence,
            evidence: vec![
                format!("Query name: {query}"),
                format!(
                    "Query length: {length} characters (threshold: {}).",
                    self.max_query_length
                ),
                format!(
                    "Shannon entropy: {entropy:.2} bits/character (threshold: {:.2}).",
                    self.entropy_threshold
                ),
                "Long or high-entropy names can be legitimate; review this indicator.".into(),
            ],
        });
    }

    fn finish(self) -> DnsAnomalyReport {
        let anomalous_queries = self.alerts.len();
        DnsAnomalyReport {
            stats: DnsAnomalyStats {
                queries_inspected: self.queries_inspected,
                anomalous_queries,
                state_evictions: self.state_evictions,
            },
            alerts: self.alerts,
        }
    }
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

/// Stateful, bounded detection pipeline for timestamp-ordered packet streams.
pub struct StreamingDetectionEngine {
    port_scan: PortScanStream,
    beacon: BeaconStream,
    dns: DnsStream,
    watermark_ns: Option<u128>,
    stats: DetectionStreamStats,
}

impl StreamingDetectionEngine {
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            port_scan: PortScanStream::new(config.clone()),
            beacon: BeaconStream::new(config.clone()),
            dns: DnsStream::new(config),
            watermark_ns: None,
            stats: DetectionStreamStats::default(),
        }
    }

    pub fn observe(&mut self, packet: &NormalizedPacket) {
        self.stats.packets_seen = self.stats.packets_seen.saturating_add(1);
        if self
            .watermark_ns
            .is_some_and(|watermark| packet.timestamp_ns < watermark)
        {
            self.stats.late_packets_ignored = self.stats.late_packets_ignored.saturating_add(1);
            return;
        }
        self.watermark_ns = Some(packet.timestamp_ns);
        self.port_scan.observe(packet);
        self.beacon.observe(packet);
        self.dns.observe(packet);
    }

    pub fn finish(self) -> DetectionReport {
        let port_scan = self.port_scan.finish();
        let beaconing = self.beacon.finish();
        let dns_anomaly = self.dns.finish();
        let state_evictions = port_scan.stats.state_evictions
            + beaconing.stats.state_evictions
            + dns_anomaly.stats.state_evictions;
        let mut stats = self.stats;
        stats.state_evictions = state_evictions;
        DetectionReport {
            stats,
            port_scan,
            beaconing,
            dns_anomaly,
        }
    }
}
