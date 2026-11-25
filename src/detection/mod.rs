//! Explainable offline traffic detections.

pub mod beacon;
pub mod dns_anomaly;
pub mod port_scan;
pub mod streaming;

use serde::Serialize;

use self::{
    beacon::{BeaconDetector, BeaconReport},
    dns_anomaly::{DnsAnomalyDetector, DnsAnomalyReport},
    port_scan::{PortScanDetector, PortScanReport},
    streaming::{DetectionStreamStats, StreamingDetectionEngine},
};
use crate::{config::DetectionConfig, models::NormalizedPacket};

#[derive(Debug, Clone, Serialize)]
pub struct DetectionReport {
    pub stats: DetectionStreamStats,
    pub port_scan: PortScanReport,
    pub beaconing: BeaconReport,
    pub dns_anomaly: DnsAnomalyReport,
}

/// Runs the currently implemented packet-level detection rules.
pub struct DetectionEngine {
    config: DetectionConfig,
}

impl DetectionEngine {
    pub fn new(config: DetectionConfig) -> Self {
        Self { config }
    }

    /// Create a bounded detection pipeline for a timestamp-ordered packet stream.
    pub fn stream(&self) -> StreamingDetectionEngine {
        StreamingDetectionEngine::new(self.config.clone())
    }

    pub fn analyze(&self, packets: &[NormalizedPacket]) -> DetectionReport {
        let mut report = DetectionReport {
            stats: DetectionStreamStats {
                packets_seen: packets.len(),
                ..DetectionStreamStats::default()
            },
            port_scan: PortScanDetector::new(self.config.clone()).analyze(packets),
            beaconing: BeaconDetector::new(self.config.clone()).analyze(packets),
            dns_anomaly: DnsAnomalyDetector::new(self.config.clone()).analyze(packets),
        };
        report.stats.state_evictions = report.port_scan.stats.state_evictions
            + report.beaconing.stats.state_evictions
            + report.dns_anomaly.stats.state_evictions;
        report
    }
}
