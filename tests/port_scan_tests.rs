use std::net::{IpAddr, Ipv4Addr};

use packethawk::{
    config::DetectionConfig,
    detection::port_scan::PortScanDetector,
    models::{NormalizedPacket, TransportProtocol},
};

fn packet(
    timestamp_ns: u128,
    source: [u8; 4],
    destination: [u8; 4],
    destination_port: u16,
) -> NormalizedPacket {
    NormalizedPacket {
        timestamp_ns,
        source_ip: IpAddr::V4(Ipv4Addr::from(source)),
        destination_ip: IpAddr::V4(Ipv4Addr::from(destination)),
        source_port: Some(40000),
        destination_port: Some(destination_port),
        protocol: TransportProtocol::Tcp,
        packet_size: 60,
        tcp_flags: Some(2),
    }
}

fn config() -> DetectionConfig {
    DetectionConfig {
        port_scan_unique_ports: 3,
        horizontal_scan_unique_hosts: 3,
        scan_window_secs: 10,
        ..DetectionConfig::default()
    }
}

#[test]
fn detects_vertical_scan_and_includes_evidence() {
    let packets = vec![
        packet(1, [192, 0, 2, 10], [198, 51, 100, 5], 22),
        packet(2, [192, 0, 2, 10], [198, 51, 100, 5], 80),
        packet(3, [192, 0, 2, 10], [198, 51, 100, 5], 443),
    ];
    let report = PortScanDetector::new(config()).analyze(&packets);
    let alert = report
        .alerts
        .iter()
        .find(|a| a.rule_id == "PORT_SCAN_VERTICAL")
        .unwrap();
    assert_eq!(
        alert.source_ip,
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
    );
    assert_eq!(
        alert.destination_ip,
        Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)))
    );
    assert!(
        alert
            .evidence
            .iter()
            .any(|line| line.contains("22, 80, 443"))
    );
    assert!((0.0..=1.0).contains(&alert.confidence));
}

#[test]
fn detects_horizontal_scan_across_hosts() {
    let packets = vec![
        packet(1, [192, 0, 2, 10], [198, 51, 100, 1], 443),
        packet(2, [192, 0, 2, 10], [198, 51, 100, 2], 443),
        packet(3, [192, 0, 2, 10], [198, 51, 100, 3], 443),
    ];
    let report = PortScanDetector::new(config()).analyze(&packets);
    assert_eq!(report.stats.horizontal_alerts, 1);
    assert!(
        report.alerts[0]
            .evidence
            .iter()
            .any(|line| line.contains("3 unique destination hosts"))
    );
}

#[test]
fn packets_outside_window_do_not_accumulate() {
    let packets = vec![
        packet(1, [192, 0, 2, 10], [198, 51, 100, 5], 22),
        packet(2, [192, 0, 2, 10], [198, 51, 100, 5], 80),
        packet(20_000_000_000, [192, 0, 2, 10], [198, 51, 100, 5], 443),
    ];
    let report = PortScanDetector::new(config()).analyze(&packets);
    assert_eq!(report.stats.vertical_alerts, 0);
}

#[test]
fn ignores_icmp_and_repeated_destination_ports() {
    let mut packets = vec![
        packet(1, [192, 0, 2, 10], [198, 51, 100, 5], 22),
        packet(2, [192, 0, 2, 10], [198, 51, 100, 5], 22),
        packet(3, [192, 0, 2, 10], [198, 51, 100, 5], 22),
    ];
    packets[2].protocol = TransportProtocol::Icmp;
    let report = PortScanDetector::new(config()).analyze(&packets);
    assert!(report.alerts.is_empty());
    assert_eq!(report.stats.packets_considered, 2);
}

#[test]
fn sorts_out_of_order_packets_before_evaluation() {
    let packets = vec![
        packet(3, [192, 0, 2, 10], [198, 51, 100, 5], 443),
        packet(1, [192, 0, 2, 10], [198, 51, 100, 5], 22),
        packet(2, [192, 0, 2, 10], [198, 51, 100, 5], 80),
    ];
    let report = PortScanDetector::new(config()).analyze(&packets);
    assert_eq!(report.stats.vertical_alerts, 1);
}
