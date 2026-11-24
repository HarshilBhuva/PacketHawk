use std::fs;

use packethawk::config::{AppConfig, ConfigError};

#[test]
fn default_configuration_is_valid() {
    AppConfig::default().validate().expect("defaults should be valid");
}

#[test]
fn loads_repository_default_configuration() {
    let config = AppConfig::load("config/default.toml")
        .expect("repository configuration should load");

    assert_eq!(config.detection.port_scan_unique_ports, 15);
    assert_eq!(config.detection.beacon_min_samples, 6);
}

#[test]
fn rejects_zero_port_scan_threshold() {
    let mut config = AppConfig::default();
    config.detection.port_scan_unique_ports = 0;

    assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_beacon_sample_count_below_three() {
    let mut config = AppConfig::default();
    config.detection.beacon_min_samples = 2;

    assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn rejects_entropy_outside_shannon_range() {
    let mut config = AppConfig::default();
    config.detection.dns_entropy_threshold = 9.0;

    assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn reports_missing_configuration_file() {
    let path = std::env::temp_dir().join(format!(
        "packethawk-missing-config-{}.toml",
        std::process::id()
    ));

    let result = AppConfig::load(path);
    assert!(matches!(result, Err(ConfigError::Io(_))));
}

#[test]
fn parses_custom_configuration() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("custom.toml");

    fs::write(&path, "[detection]\nport_scan_unique_ports = 25\n")
        .expect("write configuration");

    let config = AppConfig::load(path).expect("custom configuration should load");
    assert_eq!(config.detection.port_scan_unique_ports, 25);
    assert_eq!(config.detection.scan_window_secs, 60);
}
