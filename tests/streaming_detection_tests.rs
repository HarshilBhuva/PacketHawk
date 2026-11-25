use std::net::{IpAddr, Ipv4Addr};

use packethawk::{
    config::DetectionConfig,
    detection::DetectionEngine,
    models::{NormalizedPacket, TransportProtocol},
};

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn packet(
    timestamp_ns: u128,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    destination_port: u16,
    protocol: TransportProtocol,
    dns_query_name: Option<&str>,
) -> NormalizedPacket {
    NormalizedPacket {
        timestamp_ns,
        source_ip,
        destination_ip,
        source_port: Some(50_000),
        destination_port: Some(destination_port),
        protocol,
        packet_size: 64,
        tcp_flags: None,
        dns_query_name: dns_query_name.map(str::to_owned),
    }
}

fn config() -> DetectionConfig {
    DetectionConfig {
        port_scan_unique_ports: 3,
        horizontal_scan_unique_hosts: 3,
        scan_window_secs: 10,
        beacon_min_samples: 4,
        beacon_max_interval_cv: 0.05,
        dns_max_query_length: 10,
        dns_entropy_threshold: 3.0,
    }
}

fn scenario() -> Vec<NormalizedPacket> {
    let mut packets = vec![
        packet(
            1,
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2),
            22,
            TransportProtocol::Tcp,
            None,
        ),
        packet(
            2,
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2),
            80,
            TransportProtocol::Tcp,
            None,
        ),
        packet(
            3,
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2),
            443,
            TransportProtocol::Tcp,
            None,
        ),
        packet(
            4,
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 3),
            8080,
            TransportProtocol::Tcp,
            None,
        ),
        packet(
            5,
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 4),
            8080,
            TransportProtocol::Tcp,
            None,
        ),
        packet(
            6,
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 5),
            8080,
            TransportProtocol::Tcp,
            None,
        ),
    ];
    for second in 1..=4 {
        packets.push(packet(
            second * 1_000_000_000,
            ip(10, 0, 0, 9),
            ip(8, 8, 8, 8),
            443,
            TransportProtocol::Tcp,
            None,
        ));
    }
    packets.push(packet(
        5_000_000_000,
        ip(10, 0, 0, 1),
        ip(8, 8, 8, 8),
        53,
        TransportProtocol::Udp,
        Some("a1b2c3d4e5f6g7h8.example"),
    ));
    packets
}

#[test]
fn streaming_engine_emits_all_three_detection_families() {
    let mut engine = DetectionEngine::new(config()).stream();
    for packet in scenario() {
        engine.observe(&packet);
    }

    let report = engine.finish();

    assert_eq!(report.stats.packets_seen, 11);
    assert_eq!(report.stats.late_packets_ignored, 0);
    assert_eq!(report.port_scan.stats.vertical_alerts, 1);
    assert_eq!(report.port_scan.stats.horizontal_alerts, 1);
    assert_eq!(report.beaconing.stats.alerts, 1);
    assert_eq!(report.dns_anomaly.stats.anomalous_queries, 1);
    assert_eq!(report.stats.state_evictions, 0);
}

#[test]
fn streaming_engine_counts_and_ignores_late_packets() {
    let mut engine = DetectionEngine::new(config()).stream();
    engine.observe(&packet(
        10,
        ip(10, 0, 0, 1),
        ip(10, 0, 0, 2),
        443,
        TransportProtocol::Tcp,
        None,
    ));
    engine.observe(&packet(
        9,
        ip(10, 0, 0, 1),
        ip(10, 0, 0, 2),
        53,
        TransportProtocol::Udp,
        Some("verylongandrandom.example"),
    ));

    let report = engine.finish();

    assert_eq!(report.stats.packets_seen, 2);
    assert_eq!(report.stats.late_packets_ignored, 1);
    assert_eq!(report.dns_anomaly.stats.queries_inspected, 0);
}

#[test]
fn streaming_engine_deduplicates_dns_queries_by_source_and_name() {
    let mut engine = DetectionEngine::new(config()).stream();
    for timestamp in [1, 2] {
        engine.observe(&packet(
            timestamp,
            ip(10, 0, 0, 1),
            ip(8, 8, 8, 8),
            53,
            TransportProtocol::Udp,
            Some("a1b2c3d4e5f6g7h8.example"),
        ));
    }

    let report = engine.finish();

    assert_eq!(report.dns_anomaly.stats.queries_inspected, 2);
    assert_eq!(report.dns_anomaly.stats.anomalous_queries, 1);
}

#[test]
fn streaming_engine_suppresses_beaconing_when_intervals_are_zero() {
    let mut engine = DetectionEngine::new(config()).stream();
    for _ in 0..4 {
        engine.observe(&packet(
            1_000_000_000,
            ip(10, 0, 0, 9),
            ip(8, 8, 8, 8),
            443,
            TransportProtocol::Tcp,
            None,
        ));
    }

    let report = engine.finish();

    assert_eq!(report.beaconing.stats.alerts, 0);
}
