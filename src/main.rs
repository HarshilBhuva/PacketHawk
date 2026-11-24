use std::path::PathBuf;

use clap::{Parser, Subcommand};
use packethawk::{
    config::{AppConfig, DetectionConfig},
    detection::port_scan::PortScanDetector,
    flow::{FlowAggregator, FlowConfig, FlowDirection},
    ingest::CaptureReader,
};

#[derive(Debug, Parser)]
#[command(
    name = "packethawk",
    version,
    about = "Offline-first network threat analysis for PCAP and PCAPNG captures",
    long_about = "PacketHawk analyzes saved network captures and produces normalized packet metadata and explainable security findings."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Validate a PacketHawk TOML configuration file.
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Inspect an offline PCAP or PCAPNG capture.
    Capture {
        #[command(subcommand)]
        command: CaptureCommands,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommands {
    /// Parse and validate a configuration file.
    Check {
        /// Path to the TOML configuration file.
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum CaptureCommands {
    /// Read a capture and print a packet-ingestion summary.
    Inspect {
        /// Path to a PCAP or PCAPNG file.
        path: PathBuf,
        /// Emit the summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Aggregate capture packets into bounded network flows.
    Flows {
        /// Path to a PCAP or PCAPNG file.
        path: PathBuf,
        /// Emit the complete flow report as JSON.
        #[arg(long)]
        json: bool,
        /// Maximum number of active flows retained in memory.
        #[arg(long, default_value_t = 100_000)]
        max_active_flows: usize,
        /// Idle timeout in seconds.
        #[arg(long, default_value_t = 120)]
        idle_timeout_secs: u64,
        /// Keep each source-to-destination direction as a separate flow.
        #[arg(long)]
        directional: bool,
    },
    /// Detect vertical and horizontal port-scan patterns in a saved capture.
    Detect {
        /// Path to a PCAP or PCAPNG file.
        path: PathBuf,
        /// Optional TOML file containing detection thresholds.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Emit the full detection report as JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Config {
            command: ConfigCommands::Check { path },
        }) => {
            AppConfig::load(&path)?;
            println!("Configuration is valid: {}", path.display());
        }
        Some(Commands::Capture {
            command: CaptureCommands::Inspect { path, json },
        }) => {
            let report = CaptureReader::read_path(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Capture: {}", path.display());
                println!("Decoded packets: {}", report.packets.len());
                println!("Skipped packet frames: {}", report.skipped_packets);
            }
        }
        Some(Commands::Capture {
            command:
                CaptureCommands::Flows {
                    path,
                    json,
                    max_active_flows,
                    idle_timeout_secs,
                    directional,
                },
        }) => {
            let capture = CaptureReader::read_path(&path)?;
            let config = FlowConfig {
                max_active_flows,
                idle_timeout_ns: (idle_timeout_secs as u128).saturating_mul(1_000_000_000),
                direction: if directional {
                    FlowDirection::Directional
                } else {
                    FlowDirection::Bidirectional
                },
            };
            let mut aggregator = FlowAggregator::new(config)?;
            for packet in &capture.packets {
                aggregator.observe(packet);
            }
            let mut report = aggregator.report();

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Capture: {}", path.display());
                println!("Packets aggregated: {}", report.stats.packets_seen);
                println!("Active flows: {}", report.stats.active_flows);
                println!("Flows expired: {}", report.stats.flows_expired);
                println!("Flows evicted: {}", report.stats.flows_evicted);
                report.flows.sort_by(|left, right| {
                    right.total_bytes.cmp(&left.total_bytes).then_with(|| left.key.cmp(&right.key))
                });
                println!("\nTop flows by bytes:");
                for flow in report.flows.iter().take(10) {
                    let source_port = flow.key.source_port.map_or_else(|| "-".to_owned(), |port| port.to_string());
                    let destination_port = flow.key.destination_port.map_or_else(|| "-".to_owned(), |port| port.to_string());
                    println!(
                        "{:>8} packets  {:>12} bytes  {}:{} -> {}:{}  {:?}",
                        flow.packet_count, flow.total_bytes, flow.key.source_ip, source_port,
                        flow.key.destination_ip, destination_port, flow.key.protocol
                    );
                }
            }
        }
        Some(Commands::Capture {
            command: CaptureCommands::Detect { path, config, json },
        }) => {
            let capture = CaptureReader::read_path(&path)?;
            let settings = match config {
                Some(path) => AppConfig::load(path)?.detection,
                None => DetectionConfig::default(),
            };
            let report = PortScanDetector::new(settings).analyze(&capture.packets);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Capture: {}", path.display());
                println!("Packets considered: {}", report.stats.packets_considered);
                println!("Vertical scan alerts: {}", report.stats.vertical_alerts);
                println!("Horizontal scan alerts: {}", report.stats.horizontal_alerts);
                for alert in &report.alerts {
                    println!("\n[{:?}] {} ({:.0}% confidence)", alert.severity, alert.title, alert.confidence * 100.0);
                    for evidence in &alert.evidence {
                        println!("  - {evidence}");
                    }
                }
            }
        }
        None => {
            println!("PacketHawk is under active development.");
            println!("Run 'packethawk --help' to see available commands.");
        }
    }

    Ok(())
}
