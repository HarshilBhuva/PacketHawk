use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Transport or network-layer protocol identified during packet decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Other(u8),
}

/// Parser-independent representation of the metadata needed by the analysis engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedPacket {
    /// Capture timestamp represented as nanoseconds from the Unix epoch.
    pub timestamp_ns: u128,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: TransportProtocol,
    pub packet_size: u32,
    /// TCP flags when the packet carries a TCP header.
    pub tcp_flags: Option<u8>,
}
