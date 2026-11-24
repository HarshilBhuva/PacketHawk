use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Explainable detection result with enough context to support investigation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    /// Detection confidence in the inclusive range 0.0..=1.0.
    pub confidence: f32,
    pub evidence: Vec<String>,
}
