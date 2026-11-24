use std::path::PathBuf;

use clap::{Parser, Subcommand};
use packethawk::{config::AppConfig, ingest::CaptureReader};

#[derive(Debug, Parser)]
#[command(
    name = "packethawk",
    version,
    about = "Offline-first network threat analysis for PCAP and PCAPNG captures",
    long_about = "PacketHawk analyzes saved network captures and produces normalized packet metadata. Detection rules are under active development."
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
        None => {
            println!("PacketHawk is under active development.");
            println!("Run 'packethawk --help' to see available commands.");
        }
    }

    Ok(())
}
