use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub detection: DetectionConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            detection: DetectionConfig::default(),
        }
    }
}

impl AppConfig {
    /// Load and validate configuration from a TOML file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate values that would otherwise make detection rules unusable.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let detection = &self.detection;

        if detection.port_scan_unique_ports == 0 {
            return Err(ConfigError::Invalid(
                "detection.port_scan_unique_ports must be greater than zero".into(),
            ));
        }
        if detection.horizontal_scan_unique_hosts == 0 {
            return Err(ConfigError::Invalid(
                "detection.horizontal_scan_unique_hosts must be greater than zero".into(),
            ));
        }
        if detection.scan_window_secs == 0 {
            return Err(ConfigError::Invalid(
                "detection.scan_window_secs must be greater than zero".into(),
            ));
        }
        if detection.beacon_min_samples < 3 {
            return Err(ConfigError::Invalid(
                "detection.beacon_min_samples must be at least three".into(),
            ));
        }
        if !(0.0..=1.0).contains(&detection.beacon_max_interval_cv) {
            return Err(ConfigError::Invalid(
                "detection.beacon_max_interval_cv must be between 0 and 1".into(),
            ));
        }
        if !(1..=253).contains(&detection.dns_max_query_length) {
            return Err(ConfigError::Invalid(
                "detection.dns_max_query_length must be between 1 and 253".into(),
            ));
        }
        if !(0.0..=8.0).contains(&detection.dns_entropy_threshold) {
            return Err(ConfigError::Invalid(
                "detection.dns_entropy_threshold must be between 0 and 8".into(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectionConfig {
    pub port_scan_unique_ports: usize,
    pub horizontal_scan_unique_hosts: usize,
    pub scan_window_secs: u64,
    pub beacon_min_samples: usize,
    pub beacon_max_interval_cv: f64,
    pub dns_max_query_length: usize,
    pub dns_entropy_threshold: f64,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            port_scan_unique_ports: 15,
            horizontal_scan_unique_hosts: 20,
            scan_window_secs: 60,
            beacon_min_samples: 6,
            beacon_max_interval_cv: 0.15,
            dns_max_query_length: 80,
            dns_entropy_threshold: 3.5,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid TOML configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}
