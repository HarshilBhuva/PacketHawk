use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::TransportProtocol;

/// Five-tuple identifying a directional network flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: TransportProtocol,
}

/// Aggregated packet metadata for one directional flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkFlow {
    pub key: FlowKey,
    pub packet_count: u64,
    pub total_bytes: u64,
    pub first_seen_ns: u128,
    pub last_seen_ns: u128,
}

impl NetworkFlow {
    /// Duration of the observed flow in nanoseconds.
    pub fn duration_ns(&self) -> u128 {
        self.last_seen_ns.saturating_sub(self.first_seen_ns)
    }
}
