use std::net::{IpAddr, Ipv4Addr};

use packethawk::{
    config::DetectionConfig,
    detection::beaconing::BeaconingDetector,
    models::{NormalizedPacket, TransportProtocol},
};

fn packet(timestamp_ns: u128) -> NormalizedPacket {
    NormalizedPacket {
        timestamp_ns,
        source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        destination_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        source_port: Some(50_000),
        destination_port: Some(443),
        protocol: TransportProtocol::Tcp,
        packet_size: 60,
        tcp_flags: Some(2),
    }
}

fn config() -> DetectionConfig {
    DetectionConfig {
        beacon_min_samples: 4,
        beacon_max_interval_cv: 0.05,
        ..DetectionConfig::default()
    }
}

#[test]
fn detects_low_variance_periodic_connections() {
    let packets: Vec<_> = (0..6).map(|index| packet(index * 10_000_000_000)).collect();
    let report = BeaconingDetector::new(&config()).analyze(&packets);

    assert_eq!(report.stats.conversations_inspected, 1);
    assert_eq!(report.stats.periodic_conversations, 1);
    assert_eq!(report.alerts[0].rule_id, "NETWORK_BEACONING");
    assert!(report.alerts[0].evidence.iter().any(|line| line.contains("10.000 seconds")));
}

#[test]
fn does_not_flag_irregular_connection_intervals() {
    let times = [0, 1, 2, 20, 21, 60].map(|seconds| seconds * 1_000_000_000);
    let packets: Vec<_> = times.into_iter().map(packet).collect();
    let report = BeaconingDetector::new(&config()).analyze(&packets);

    assert_eq!(report.stats.periodic_conversations, 0);
}

#[test]
fn requires_configured_number_of_intervals() {
    let settings = DetectionConfig {
        beacon_min_samples: 5,
        ..config()
    };
    let packets = vec![packet(0), packet(10_000_000_000), packet(20_000_000_000)];
    let report = BeaconingDetector::new(&settings).analyze(&packets);

    assert_eq!(report.stats.periodic_conversations, 0);
}

#[test]
fn sorts_out_of_order_capture_timestamps() {
    let packets = vec![
        packet(20_000_000_000),
        packet(0),
        packet(10_000_000_000),
        packet(30_000_000_000),
        packet(40_000_000_000),
        packet(50_000_000_000),
    ];
    let report = BeaconingDetector::new(&config()).analyze(&packets);

    assert_eq!(report.stats.periodic_conversations, 1);
}

#[test]
fn ignores_non_tcp_udp_and_missing_destination_ports() {
    let mut icmp = packet(0);
    icmp.protocol = TransportProtocol::Icmp;
    let mut no_port = packet(1);
    no_port.destination_port = None;
    let report = BeaconingDetector::new(&config()).analyze(&[icmp, no_port]);

    assert_eq!(report.stats.conversations_inspected, 0);
    assert!(report.alerts.is_empty());
}

#[test]
fn duplicate_timestamps_do_not_create_zero_length_intervals() {
    let packets = vec![
        packet(0),
        packet(0),
        packet(10_000_000_000),
        packet(10_000_000_000),
        packet(20_000_000_000),
        packet(30_000_000_000),
        packet(40_000_000_000),
        packet(50_000_000_000),
    ];
    let report = BeaconingDetector::new(&config()).analyze(&packets);

    assert_eq!(report.stats.periodic_conversations, 1);
}
