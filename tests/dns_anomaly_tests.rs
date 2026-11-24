use std::net::{IpAddr, Ipv4Addr};

use packethawk::{
    config::DetectionConfig,
    detection::dns_anomaly::DnsAnomalyDetector,
    models::{NormalizedPacket, TransportProtocol},
};

fn packet(query: &str) -> NormalizedPacket {
    NormalizedPacket {
        timestamp_ns: 1,
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        destination_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        source_port: Some(53000),
        destination_port: Some(53),
        protocol: TransportProtocol::Udp,
        packet_size: 90,
        tcp_flags: None,
        dns_query_name: Some(query.to_owned()),
    }
}

#[test]
fn flags_long_dns_query_names() {
    let config = DetectionConfig {
        dns_max_query_length: 20,
        dns_entropy_threshold: 8.0,
        ..DetectionConfig::default()
    };
    let query = "this-is-a-very-long-subdomain.example.test";
    let report = DnsAnomalyDetector::new(config).analyze(&[packet(query)]);

    assert_eq!(report.stats.queries_inspected, 1);
    assert_eq!(report.stats.anomalous_queries, 1);
    assert_eq!(report.alerts[0].rule_id, "DNS_QUERY_ANOMALY");
    assert!(
        report.alerts[0]
            .evidence
            .iter()
            .any(|line| line.contains(query))
    );
}

#[test]
fn flags_high_entropy_dns_query_names() {
    let config = DetectionConfig {
        dns_max_query_length: 253,
        dns_entropy_threshold: 3.0,
        ..DetectionConfig::default()
    };
    let report = DnsAnomalyDetector::new(config).analyze(&[packet("a8f3k9x2m7q4v6z1.example")]);

    assert_eq!(report.stats.anomalous_queries, 1);
}

#[test]
fn suppresses_duplicate_source_and_query_pairs() {
    let config = DetectionConfig {
        dns_max_query_length: 10,
        dns_entropy_threshold: 8.0,
        ..DetectionConfig::default()
    };
    let query = packet("long-name-that-exceeds-limit.example");
    let report = DnsAnomalyDetector::new(config).analyze(&[query.clone(), query]);

    assert_eq!(report.stats.queries_inspected, 2);
    assert_eq!(report.stats.anomalous_queries, 1);
}

#[test]
fn ignores_packets_without_dns_query_metadata() {
    let config = DetectionConfig::default();
    let mut non_dns = packet("ordinary.example");
    non_dns.dns_query_name = None;
    let report = DnsAnomalyDetector::new(config).analyze(&[non_dns]);

    assert_eq!(report.stats.queries_inspected, 0);
    assert!(report.alerts.is_empty());
}
