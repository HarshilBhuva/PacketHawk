use std::net::{IpAddr, Ipv4Addr};

use packethawk::{
    flow::{FlowAggregator, FlowConfig, FlowDirection, FlowError},
    models::{NormalizedPacket, TransportProtocol},
};

fn packet(
    timestamp_ns: u128,
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    packet_size: u32,
) -> NormalizedPacket {
    NormalizedPacket {
        timestamp_ns,
        source_ip: IpAddr::V4(Ipv4Addr::from(source)),
        destination_ip: IpAddr::V4(Ipv4Addr::from(destination)),
        source_port: Some(source_port),
        destination_port: Some(destination_port),
        protocol: TransportProtocol::Tcp,
        packet_size,
        tcp_flags: None,
    }
}

fn config() -> FlowConfig {
    FlowConfig {
        max_active_flows: 100,
        idle_timeout_ns: 100,
        direction: FlowDirection::Bidirectional,
    }
}

#[test]
fn reverse_packets_share_one_bidirectional_flow() {
    let mut aggregator = FlowAggregator::new(config()).unwrap();
    aggregator.observe(&packet(10, [10, 0, 0, 1], [10, 0, 0, 2], 50000, 443, 60));
    aggregator.observe(&packet(20, [10, 0, 0, 2], [10, 0, 0, 1], 443, 50000, 70));

    let report = aggregator.report();
    assert_eq!(report.flows.len(), 1);
    let flow = &report.flows[0];
    assert_eq!(flow.packet_count, 2);
    assert_eq!(flow.total_bytes, 130);
    assert_eq!(flow.forward_packets, 1);
    assert_eq!(flow.reverse_packets, 1);
    assert_eq!(flow.forward_bytes, 60);
    assert_eq!(flow.reverse_bytes, 70);
    assert_eq!(flow.first_seen_ns, 10);
    assert_eq!(flow.last_seen_ns, 20);
    assert_eq!(flow.duration_ns(), 10);
}

#[test]
fn directional_mode_keeps_reverse_traffic_separate() {
    let mut settings = config();
    settings.direction = FlowDirection::Directional;
    let mut aggregator = FlowAggregator::new(settings).unwrap();
    aggregator.observe(&packet(10, [10, 0, 0, 1], [10, 0, 0, 2], 50000, 443, 60));
    aggregator.observe(&packet(20, [10, 0, 0, 2], [10, 0, 0, 1], 443, 50000, 70));

    let report = aggregator.report();
    assert_eq!(report.flows.len(), 2);
    assert!(report.flows.iter().all(|flow| flow.forward_packets == 1));
    assert!(report.flows.iter().all(|flow| flow.reverse_packets == 0));
}

#[test]
fn out_of_order_timestamps_preserve_minimum_and_maximum() {
    let mut aggregator = FlowAggregator::new(config()).unwrap();
    aggregator.observe(&packet(30, [10, 0, 0, 1], [10, 0, 0, 2], 50000, 443, 60));
    aggregator.observe(&packet(20, [10, 0, 0, 1], [10, 0, 0, 2], 50000, 443, 70));

    let flow = &aggregator.report().flows[0];
    assert_eq!(flow.first_seen_ns, 20);
    assert_eq!(flow.last_seen_ns, 30);
    assert_eq!(flow.packet_count, 2);
}

#[test]
fn idle_flows_expire_when_capture_time_advances() {
    let mut aggregator = FlowAggregator::new(config()).unwrap();
    aggregator.observe(&packet(10, [10, 0, 0, 1], [10, 0, 0, 2], 50000, 443, 60));
    aggregator.observe(&packet(109, [10, 0, 0, 3], [10, 0, 0, 4], 50001, 443, 60));
    assert_eq!(aggregator.report().stats.flows_expired, 0);

    aggregator.observe(&packet(110, [10, 0, 0, 5], [10, 0, 0, 6], 50002, 443, 60));
    let report = aggregator.report();
    assert_eq!(report.stats.flows_expired, 1);
    assert_eq!(report.stats.active_flows, 2);
}

#[test]
fn capacity_evicts_the_least_recently_seen_flow() {
    let mut settings = config();
    settings.max_active_flows = 1;
    let mut aggregator = FlowAggregator::new(settings).unwrap();
    aggregator.observe(&packet(10, [10, 0, 0, 1], [10, 0, 0, 2], 50000, 443, 60));
    aggregator.observe(&packet(20, [10, 0, 0, 3], [10, 0, 0, 4], 50001, 443, 60));

    let report = aggregator.report();
    assert_eq!(report.stats.flows_evicted, 1);
    assert_eq!(report.stats.active_flows, 1);
    assert_eq!(report.flows[0].key.source_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
}

#[test]
fn zero_capacity_and_zero_timeout_are_rejected() {
    let mut settings = config();
    settings.max_active_flows = 0;
    assert!(matches!(FlowAggregator::new(settings), Err(FlowError::ZeroCapacity)));

    let mut settings = config();
    settings.idle_timeout_ns = 0;
    assert!(matches!(FlowAggregator::new(settings), Err(FlowError::ZeroIdleTimeout)));
}
