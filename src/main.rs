use std::path::PathBuf;

use clap::{Parser, Subcommand};
use packethawk::config::AppConfig;

#[derive(Debug, Parser)]
#[command(
    name = "packethawk",
    version,
    about = "Offline-first network threat analysis for PCAP and PCAPNG captures",
    long_about = "PacketHawk analyzes network captures and produces explainable security findings. The current development milestone provides the project foundation and configuration validation."
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
}

#[derive(Debug, Subcommand)]
enum ConfigCommands {
    /// Parse and validate a configuration file.
    Check {
        /// Path to the TOML configuration file.
        path: PathBuf,
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
        None => {
            println!("PacketHawk is under active development.");
            println!("Run 'packethawk --help' to see available commands.");
        }
    }

    Ok(())
}
