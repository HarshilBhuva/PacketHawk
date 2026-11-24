//! Bounded packet-to-flow aggregation for offline capture analysis.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::models::{FlowKey, NetworkFlow, NormalizedPacket};

/// Determines whether reverse-direction packets share the same flow record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    /// Canonicalize endpoint order and aggregate both directions together.
    Bidirectional,
    /// Preserve source-to-destination direction in the flow key.
    Directional,
}

impl Default for FlowDirection {
    fn default() -> Self {
        Self::Bidirectional
    }
}

/// Resource and identity policy for the flow table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowConfig {
    pub max_active_flows: usize,
    /// Idle timeout in nanoseconds.
    pub idle_timeout_ns: u128,
    pub direction: FlowDirection,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            max_active_flows: 100_000,
            idle_timeout_ns: 120_000_000_000,
            direction: FlowDirection::Bidirectional,
        }
    }
}

impl FlowConfig {
    pub fn validate(&self) -> Result<(), FlowError> {
        if self.max_active_flows == 0 {
            return Err(FlowError::ZeroCapacity);
        }
        if self.idle_timeout_ns == 0 {
            return Err(FlowError::ZeroIdleTimeout);
        }
        Ok(())
    }
}

/// Cumulative counters for one aggregation run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowStats {
    pub packets_seen: u64,
    pub flows_created: u64,
    pub flows_expired: u64,
    pub flows_evicted: u64,
    pub active_flows: usize,
}

/// Snapshot suitable for JSON output or downstream detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowReport {
    pub stats: FlowStats,
    pub flows: Vec<NetworkFlow>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FlowError {
    #[error("max_active_flows must be greater than zero")]
    ZeroCapacity,
    #[error("idle_timeout_ns must be greater than zero")]
    ZeroIdleTimeout,
}

/// Maintains a bounded set of active flows.
///
/// The hash map provides constant-time flow lookup. A sorted recency index
/// supports deterministic idle expiry and capacity eviction without scanning
/// the full table for every packet.
pub struct FlowAggregator {
    config: FlowConfig,
    flows: HashMap<FlowKey, NetworkFlow>,
    recency: BTreeSet<(u128, FlowKey)>,
    watermark_ns: Option<u128>,
    stats: FlowStats,
}

impl FlowAggregator {
    pub fn new(config: FlowConfig) -> Result<Self, FlowError> {
        config.validate()?;
        Ok(Self {
            config,
            flows: HashMap::new(),
            recency: BTreeSet::new(),
            watermark_ns: None,
            stats: FlowStats::default(),
        })
    }

    /// Add one normalized packet to the appropriate flow.
    pub fn observe(&mut self, packet: &NormalizedPacket) {
        self.stats.packets_seen = self.stats.packets_seen.saturating_add(1);
        self.watermark_ns = Some(
            self.watermark_ns
                .map_or(packet.timestamp_ns, |current| current.max(packet.timestamp_ns)),
        );
        self.expire_idle_flows();

        let (key, is_forward) = self.flow_key(packet);
        if let Some(mut flow) = self.flows.remove(&key) {
            self.recency.remove(&(flow.last_seen_ns, key.clone()));
            flow.first_seen_ns = flow.first_seen_ns.min(packet.timestamp_ns);
            flow.last_seen_ns = flow.last_seen_ns.max(packet.timestamp_ns);
            flow.packet_count = flow.packet_count.saturating_add(1);
            flow.total_bytes = flow.total_bytes.saturating_add(packet.packet_size as u64);
            if is_forward {
                flow.forward_packets = flow.forward_packets.saturating_add(1);
                flow.forward_bytes = flow.forward_bytes.saturating_add(packet.packet_size as u64);
            } else {
                flow.reverse_packets = flow.reverse_packets.saturating_add(1);
                flow.reverse_bytes = flow.reverse_bytes.saturating_add(packet.packet_size as u64);
            }
            self.recency.insert((flow.last_seen_ns, key.clone()));
            self.flows.insert(key, flow);
        } else {
            if self.flows.len() >= self.config.max_active_flows {
                self.evict_oldest_flow();
            }
            let size = packet.packet_size as u64;
            let flow = NetworkFlow {
                key: key.clone(),
                packet_count: 1,
                total_bytes: size,
                forward_packets: if is_forward { 1 } else { 0 },
                reverse_packets: if is_forward { 0 } else { 1 },
                forward_bytes: if is_forward { size } else { 0 },
                reverse_bytes: if is_forward { 0 } else { size },
                first_seen_ns: packet.timestamp_ns,
                last_seen_ns: packet.timestamp_ns,
            };
            self.recency.insert((packet.timestamp_ns, key.clone()));
            self.flows.insert(key, flow);
            self.stats.flows_created = self.stats.flows_created.saturating_add(1);
        }
        self.stats.active_flows = self.flows.len();
    }

    /// Return a stable snapshot ordered by the flow key.
    pub fn report(&self) -> FlowReport {
        let mut flows: Vec<_> = self.flows.values().cloned().collect();
        flows.sort_by(|left, right| left.key.cmp(&right.key));
        let mut stats = self.stats.clone();
        stats.active_flows = flows.len();
        FlowReport { stats, flows }
    }

    fn flow_key(&self, packet: &NormalizedPacket) -> (FlowKey, bool) {
        let source = (packet.source_ip, packet.source_port);
        let destination = (packet.destination_ip, packet.destination_port);
        let is_forward = self.config.direction == FlowDirection::Directional || source <= destination;
        let (source_ip, source_port, destination_ip, destination_port) = if is_forward {
            (
                packet.source_ip,
                packet.source_port,
                packet.destination_ip,
                packet.destination_port,
            )
        } else {
            (
                packet.destination_ip,
                packet.destination_port,
                packet.source_ip,
                packet.source_port,
            )
        };
        (
            FlowKey {
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol: packet.protocol,
            },
            is_forward,
        )
    }

    fn expire_idle_flows(&mut self) {
        let Some(watermark) = self.watermark_ns else {
            return;
        };
        loop {
            let Some((last_seen, key)) = self.recency.first().cloned() else {
                break;
            };
            if watermark.saturating_sub(last_seen) < self.config.idle_timeout_ns {
                break;
            }
            self.recency.pop_first();
            self.flows.remove(&key);
            self.stats.flows_expired = self.stats.flows_expired.saturating_add(1);
        }
        self.stats.active_flows = self.flows.len();
    }

    fn evict_oldest_flow(&mut self) {
        if let Some((_, key)) = self.recency.pop_first() {
            self.flows.remove(&key);
            self.stats.flows_evicted = self.stats.flows_evicted.saturating_add(1);
        }
    }
}
