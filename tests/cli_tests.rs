use std::process::{Command, Output};

use tempfile::tempdir;

fn run_cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_packethawk"))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("PacketHawk CLI should start")
}

fn empty_pcap() -> Vec<u8> {
    vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
    ]
}

fn write_empty_capture() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("empty.pcap");
    std::fs::write(&path, empty_pcap()).expect("capture fixture should be written");
    (directory, path)
}

#[test]
fn help_and_version_are_available() {
    let help = run_cli(&["--help"]);
    assert!(help.status.success());
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(
        stdout.contains("Usage:"),
        "unexpected help output: {stdout}"
    );
    assert!(
        stdout.contains("Commands:"),
        "unexpected help output: {stdout}"
    );
    assert!(stdout.contains("capture"));

    let version = run_cli(&["--version"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("packethawk 0.1.0"));
}

#[test]
fn documented_default_configuration_command_succeeds() {
    let output = run_cli(&["config", "check", "config/default.toml"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Configuration is valid"));
}

#[test]
fn inspect_supports_human_readable_and_json_output() {
    let (_directory, path) = write_empty_capture();
    let path = path.to_str().expect("temporary path should be UTF-8");

    let human = run_cli(&["capture", "inspect", path]);
    assert!(
        human.status.success(),
        "{}",
        String::from_utf8_lossy(&human.stderr)
    );
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(stdout.contains("Decoded packets: 0"));
    assert!(stdout.contains("Skipped packet frames: 0"));

    let json = run_cli(&["capture", "inspect", path, "--json"]);
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("inspect JSON should be valid");
    assert_eq!(report["packets"].as_array().map(Vec::len), Some(0));
    assert_eq!(report["skipped_packets"], 0);
}

#[test]
fn flow_and_detection_commands_accept_a_valid_empty_capture() {
    let (_directory, path) = write_empty_capture();
    let path = path.to_str().expect("temporary path should be UTF-8");

    let flows = run_cli(&["capture", "flows", path]);
    assert!(
        flows.status.success(),
        "{}",
        String::from_utf8_lossy(&flows.stderr)
    );
    assert!(String::from_utf8_lossy(&flows.stdout).contains("Packets aggregated: 0"));

    let detect = run_cli(&["capture", "detect", path]);
    assert!(
        detect.status.success(),
        "{}",
        String::from_utf8_lossy(&detect.stderr)
    );
    assert!(String::from_utf8_lossy(&detect.stdout).contains("Packets analyzed: 0"));
}

#[test]
fn unsupported_capture_format_returns_a_nonzero_exit_code() {
    let directory = tempdir().expect("temporary directory should be created");
    let path = directory.path().join("invalid.pcap");
    std::fs::write(&path, b"not a capture").expect("invalid fixture should be written");

    let output = run_cli(&[
        "capture",
        "inspect",
        path.to_str().expect("temporary path should be UTF-8"),
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.trim().is_empty(),
        "failed command should explain the error"
    );
}
