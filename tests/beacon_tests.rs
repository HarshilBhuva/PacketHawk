use std::net::{IpAddr, Ipv4Addr};

use packethawk::{
    config::DetectionConfig,
    detection::beacon::BeaconDetector,
    models::{NormalizedPacket, TransportProtocol},
};

fn packet(timestamp_ns: u128) -> NormalizedPacket {
    NormalizedPacket {
        timestamp_ns,
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        destination_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        source_port: Some(50000),
        destination_port: Some(443),
        protocol: TransportProtocol::Tcp,
        packet_size: 90,
        tcp_flags: Some(0x10),
        dns_query_name: None,
    }
}

fn config() -> DetectionConfig {
    DetectionConfig {
        beacon_min_samples: 5,
        beacon_max_interval_cv: 0.10,
        ..DetectionConfig::default()
    }
}

#[test]
fn detects_regular_periodic_conversation() {
    let packets: Vec<_> = (0..6).map(|index| packet(index * 5_000_000_000)).collect();
    let report = BeaconDetector::new(config()).analyze(&packets);
    assert_eq!(report.stats.alerts, 1);
    assert_eq!(report.alerts[0].rule_id, "NETWORK_BEACONING");
    assert!(
        report.alerts[0]
            .evidence
            .iter()
            .any(|line| line.contains("Mean interval"))
    );
}

#[test]
fn ignores_irregular_intervals() {
    let packets = vec![
        packet(0),
        packet(1_000_000_000),
        packet(4_000_000_000),
        packet(5_000_000_000),
        packet(11_000_000_000),
        packet(12_000_000_000),
    ];
    let report = BeaconDetector::new(config()).analyze(&packets);
    assert_eq!(report.stats.alerts, 0);
}

#[test]
fn requires_configured_minimum_sample_count() {
    let packets: Vec<_> = (0..4).map(|index| packet(index * 2_000_000_000)).collect();
    let report = BeaconDetector::new(config()).analyze(&packets);
    assert_eq!(report.stats.alerts, 0);
}

#[test]
fn ignores_duplicate_timestamps_and_non_transport_protocols() {
    let mut packets: Vec<_> = (0..5).map(|index| packet(index * 2_000_000_000)).collect();
    packets.push(packet(8_000_000_000));
    packets[5].timestamp_ns = packets[4].timestamp_ns;
    packets[0].protocol = TransportProtocol::Icmp;
    let report = BeaconDetector::new(config()).analyze(&packets);
    assert_eq!(report.stats.alerts, 0);
}

#[test]
fn handles_out_of_order_timestamps() {
    let packets = vec![
        packet(10_000_000_000),
        packet(0),
        packet(8_000_000_000),
        packet(2_000_000_000),
        packet(6_000_000_000),
        packet(4_000_000_000),
    ];
    let report = BeaconDetector::new(config()).analyze(&packets);
    assert_eq!(report.stats.alerts, 1);
}
