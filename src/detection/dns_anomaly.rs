use std::{collections::HashSet, net::IpAddr};

use serde::{Deserialize, Serialize};

use crate::{
    config::DetectionConfig,
    models::{NormalizedPacket, SecurityAlert, Severity},
};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAnomalyStats {
    pub queries_inspected: usize,
    pub anomalous_queries: usize,
    pub state_evictions: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsAnomalyReport {
    pub stats: DnsAnomalyStats,
    pub alerts: Vec<SecurityAlert>,
}

/// Flags unusually long or high-entropy DNS question names for analyst review.
pub struct DnsAnomalyDetector {
    max_query_length: usize,
    entropy_threshold: f64,
}

impl DnsAnomalyDetector {
    pub fn new(config: DetectionConfig) -> Self {
        Self {
            max_query_length: config.dns_max_query_length,
            entropy_threshold: config.dns_entropy_threshold,
        }
    }

    pub fn analyze(&self, packets: &[NormalizedPacket]) -> DnsAnomalyReport {
        let mut seen = HashSet::<(IpAddr, String)>::new();
        let mut alerts = Vec::new();
        let mut queries_inspected = 0usize;

        for packet in packets {
            let Some(query) = packet.dns_query_name.as_deref() else {
                continue;
            };
            queries_inspected = queries_inspected.saturating_add(1);
            let normalized = query.to_ascii_lowercase();
            if !seen.insert((packet.source_ip, normalized)) {
                continue;
            }

            let length = query.len();
            let entropy = shannon_entropy(query.as_bytes());
            let is_long = length > self.max_query_length;
            let is_high_entropy = entropy >= self.entropy_threshold;
            if !is_long && !is_high_entropy {
                continue;
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
            alerts.push(SecurityAlert {
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

        let anomalous_queries = alerts.len();
        DnsAnomalyReport {
            stats: DnsAnomalyStats {
                queries_inspected,
                anomalous_queries,
                state_evictions: 0,
            },
            alerts,
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
