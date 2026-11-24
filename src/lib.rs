//! PacketHawk's reusable domain and configuration layer.
//!
//! The library is intentionally independent of the CLI so packet ingestion,
//! flow aggregation, detection, and reporting can be tested in isolation.

pub mod config;
pub mod detection;
pub mod flow;
pub mod ingest;
pub mod models;
