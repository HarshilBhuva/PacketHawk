use std::net::{IpAddr, Ipv4Addr};

use packethawk::{
    config::DetectionConfig,
    detection::PortScanDetector,
    models::{NormalizedPacket, TransportProtocol},
};

fn packet(ts: u128, src: [u8; 4], dst: [u8; 4], dport: u16) -> NormalizedPacket {
    NormalizedPacket {
        timestamp_ns: ts,
        source_ip: IpAddr::V4(Ipv4Addr::from(src)),
        destination_ip: IpAddr::V4(Ipv4Addr::from(dst)),
        source_port: Some(50000),
        destination_port: Some(dport),
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
fn vertical_scan_alerts_on_unique_destination_ports() {
    let mut detector = PortScanDetector::new(&config(), 100);
    detector.observe(&packet(1, [10, 0, 0, 1], [10, 0, 0, 2], 22));
    detector.observe(&packet(2, [10, 0, 0, 1], [10, 0, 0, 2], 80));
    let alerts = detector.observe(&packet(3, [10, 0, 0, 1], [10, 0, 0, 2], 443));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "PORT_SCAN_VERTICAL");
    assert_eq!(
        alerts[0].destination_ip,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
    );
    assert!(alerts[0].evidence[0].contains("3 unique destination ports"));
}

#[test]
fn horizontal_scan_alerts_on_unique_hosts_at_same_port() {
    let mut detector = PortScanDetector::new(&config(), 100);
    detector.observe(&packet(1, [10, 0, 0, 1], [10, 0, 0, 2], 443));
    detector.observe(&packet(2, [10, 0, 0, 1], [10, 0, 0, 3], 443));
    let alerts = detector.observe(&packet(3, [10, 0, 0, 1], [10, 0, 0, 4], 443));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "PORT_SCAN_HORIZONTAL");
    assert!(alerts[0].evidence[0].contains("3 unique destination hosts"));
}

#[test]
fn repeated_packets_to_same_port_do_not_trigger_vertical_scan() {
    let mut detector = PortScanDetector::new(&config(), 100);
    for ts in 1..20 {
        assert!(
            detector
                .observe(&packet(ts, [10, 0, 0, 1], [10, 0, 0, 2], 443))
                .is_empty()
        );
    }
}

#[test]
fn late_packets_outside_watermark_window_are_ignored() {
    let mut detector = PortScanDetector::new(&config(), 100);
    detector.observe(&packet(20_000_000_000, [10, 0, 0, 1], [10, 0, 0, 2], 22));
    assert!(
        detector
            .observe(&packet(1, [10, 0, 0, 1], [10, 0, 0, 2], 80))
            .is_empty()
    );
}

#[test]
fn non_tcp_udp_packets_are_ignored() {
    let mut detector = PortScanDetector::new(&config(), 100);
    let mut pkt = packet(1, [10, 0, 0, 1], [10, 0, 0, 2], 22);
    pkt.protocol = TransportProtocol::Icmp;
    assert!(detector.observe(&pkt).is_empty());
}

#[test]
fn tracker_state_is_bounded() {
    let mut detector = PortScanDetector::new(&config(), 2);
    for n in 1u8..10 {
        detector.observe(&packet(u128::from(n), [10, 0, 0, n], [10, 0, 1, n], 443));
    }
    assert!(detector.active_tracker_count() <= 2);
}
