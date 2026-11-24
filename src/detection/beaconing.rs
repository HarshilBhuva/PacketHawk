use std::{
    collections::{hash_map::Entry, HashMap},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};

use crate::{
    config::DetectionConfig,
    models::{NormalizedPacket, SecurityAlert, Severity, TransportProtocol},
};

const MAX_CONVERSATIONS: usize = 100_000;
const MAX_TIMESTAMPS_PER_CONVERSATION: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConversationKey {
    source: IpAddr,
    destination: IpAddr,
    destination_port: u16,
    protocol: TransportProtocol,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconingStats {
    pub conversations_inspected: usize,
    pub periodic_conversations: usize,
    pub timestamps_considered: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconingReport {
    pub stats: BeaconingStats,
    pub alerts: Vec<SecurityAlert>,
}

/// Detects repeated TCP/UDP conversations with low inter-arrival variability.
///
/// This is a batch detector for saved captures. Conversation count and retained
/// timestamps are capped to keep additional analysis state predictable.
pub struct BeaconingDetector {
    min_intervals: usize,
    max_interval_cv: f64,
}

impl BeaconingDetector {
    pub fn new(config: &DetectionConfig) -> Self {
        Self {
            min_intervals: config.beacon_min_samples,
            max_interval_cv: config.beacon_max_interval_cv,
        }
    }

    pub fn analyze(&self, packets: &[NormalizedPacket]) -> BeaconingReport {
        let mut conversations: HashMap<ConversationKey, Vec<u128>> = HashMap::new();
        let mut timestamps_considered = 0usize;

        for packet in packets {
            if !matches!(
                packet.protocol,
                TransportProtocol::Tcp | TransportProtocol::Udp
            ) {
                continue;
            }
            let Some(destination_port) = packet.destination_port else {
                continue;
            };
            let key = ConversationKey {
                source: packet.source_ip,
                destination: packet.destination_ip,
                destination_port,
                protocol: packet.protocol,
            };

            match conversations.entry(key) {
                Entry::Occupied(mut entry) => {
                    let timestamps = entry.get_mut();
                    if timestamps.len() < MAX_TIMESTAMPS_PER_CONVERSATION {
                        timestamps.push(packet.timestamp_ns);
                        timestamps_considered = timestamps_considered.saturating_add(1);
                    }
                }
                Entry::Vacant(entry) if conversations.len() < MAX_CONVERSATIONS => {
                    entry.insert(vec![packet.timestamp_ns]);
                    timestamps_considered = timestamps_considered.saturating_add(1);
                }
                Entry::Vacant(_) => {}
            }
        }

        let conversations_inspected = conversations.len();
        let mut alerts = Vec::new();
        for (key, mut timestamps) in conversations {
            timestamps.sort_unstable();
            timestamps.dedup();
            let intervals: Vec<f64> = timestamps
                .windows(2)
                .map(|pair| pair[1].saturating_sub(pair[0]) as f64)
                .collect();
            if intervals.len() < self.min_intervals {
                continue;
            }

            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            if mean <= 0.0 {
                continue;
            }
            let variance = intervals
                .iter()
                .map(|interval| (interval - mean).powi(2))
                .sum::<f64>()
                / intervals.len() as f64;
            let coefficient_of_variation = variance.sqrt() / mean;
            if coefficient_of_variation > self.max_interval_cv {
                continue;
            }

            let mean_seconds = mean / 1_000_000_000.0;
            let confidence = (0.6
                + (self.max_interval_cv - coefficient_of_variation).max(0.0) * 0.3)
                .clamp(0.6, 0.95);
            alerts.push(SecurityAlert {
                rule_id: "NETWORK_BEACONING".into(),
                title: "Potential periodic network beacon".into(),
                severity: Severity::Medium,
                source_ip: Some(key.source),
                destination_ip: Some(key.destination),
                confidence,
                evidence: vec![
                    format!("Observed {} inter-arrival intervals.", intervals.len()),
                    format!("Mean interval: {mean_seconds:.3} seconds."),
                    format!("Interval coefficient of variation: {coefficient_of_variation:.4}."),
                    format!("Configured maximum CV: {:.4}.", self.max_interval_cv),
                    format!("Destination port: {} ({:?}).", key.destination_port, key.protocol),
                    "Periodic traffic can be legitimate; correlate with process and destination context.".into(),
                ],
            });
        }

        alerts.sort_by(|left, right| {
            left.source_ip
                .cmp(&right.source_ip)
                .then_with(|| left.destination_ip.cmp(&right.destination_ip))
        });
        let periodic_conversations = alerts.len();
        BeaconingReport {
            stats: BeaconingStats {
                conversations_inspected,
                periodic_conversations,
                timestamps_considered,
            },
            alerts,
        }
    }
}
