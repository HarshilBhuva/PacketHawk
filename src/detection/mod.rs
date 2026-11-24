//! Explainable offline traffic detections.

pub mod beacon;
pub mod port_scan;

use serde::Serialize;

use self::{
    beacon::{BeaconDetector, BeaconReport},
    port_scan::{PortScanDetector, PortScanReport},
};
use crate::{config::DetectionConfig, models::NormalizedPacket};

#[derive(Debug, Clone, Serialize)]
pub struct DetectionReport {
    pub port_scan: PortScanReport,
    pub beaconing: BeaconReport,
}

/// Runs the currently implemented packet-level detection rules.
pub struct DetectionEngine {
    config: DetectionConfig,
}

impl DetectionEngine {
    pub fn new(config: DetectionConfig) -> Self {
        Self { config }
    }

    pub fn analyze(&self, packets: &[NormalizedPacket]) -> DetectionReport {
        DetectionReport {
            port_scan: PortScanDetector::new(self.config.clone()).analyze(packets),
            beaconing: BeaconDetector::new(self.config.clone()).analyze(packets),
        }
    }
}
