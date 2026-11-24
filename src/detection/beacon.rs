use std::{collections::HashMap, net::IpAddr};

use serde::{Deserialize, Serialize};

use crate::{
    config::DetectionConfig,
    models::{NormalizedPacket, SecurityAlert, Severity, TransportProtocol},
};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconStats {
    pub conversations_considered: usize,
    pub alerts: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconReport {
    pub stats: BeaconStats,
    pub alerts: Vec<SecurityAlert>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConversationKey {
    source: IpAddr,
    destination: IpAddr,
    destination_port: u16,
    protocol: TransportProtocol,
}

/// Detects repeated conversations with unusually regular packet intervals.
///
/// This is a statistical heuristic over packet timestamps. It does not inspect
/// application payloads and should be interpreted as triage context only.
pub struct BeaconDetector {
    config: DetectionConfig,
}

impl BeaconDetector {
    pub fn new(config: DetectionConfig) -> Self {
        Self { config }
    }

    pub fn analyze(&self, packets: &[NormalizedPacket]) -> BeaconReport {
        let mut conversations: HashMap<ConversationKey, Vec<u128>> = HashMap::new();

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
            conversations
                .entry(key)
                .or_default()
                .push(packet.timestamp_ns);
        }

        let conversations_considered = conversations.len();
        let mut alerts = Vec::new();

        for (key, mut timestamps) in conversations {
            if timestamps.len() < self.config.beacon_min_samples {
                continue;
            }
            timestamps.sort_unstable();

            let intervals: Vec<f64> = timestamps
                .windows(2)
                .map(|pair| pair[1].saturating_sub(pair[0]) as f64)
                .collect();
            if intervals.contains(&0.0) {
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
            let standard_deviation = variance.sqrt();
            let coefficient_of_variation = standard_deviation / mean;

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
                    format!("Observed {} packets", timestamps.len()),
                    format!("Mean interval: {:.3} ms", mean / 1_000_000.0),
                    format!(
                        "Interval standard deviation: {:.3} ms",
                        standard_deviation / 1_000_000.0
                    ),
                    format!(
                        "Interval coefficient of variation: {:.4}",
                        coefficient_of_variation
                    ),
                    format!(
                        "Configured maximum interval CV: {:.4}",
                        self.config.beacon_max_interval_cv
                    ),
                    format!(
                        "Capture window: {}..={} ns",
                        timestamps[0],
                        timestamps[timestamps.len() - 1]
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
                conversations_considered,
                alerts: alerts.len(),
            },
            alerts,
        }
    }
}
