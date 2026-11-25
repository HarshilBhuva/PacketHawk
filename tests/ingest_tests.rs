use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr},
};

use packethawk::{ingest::CaptureReader, models::TransportProtocol};

fn ethernet_ipv4_tcp() -> Vec<u8> {
    let mut frame = vec![0u8; 14 + 20 + 20];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut frame[14..34];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&40u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&[192, 0, 2, 10]);
    ip[16..20].copy_from_slice(&[198, 51, 100, 20]);
    let tcp = &mut frame[34..54];
    tcp[0..2].copy_from_slice(&49152u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x02;
    frame
}

fn pcap_fixture(frame: &[u8]) -> Vec<u8> {
    let mut bytes = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
    ];
    bytes.extend_from_slice(&7u32.to_le_bytes());
    bytes.extend_from_slice(&500_000u32.to_le_bytes());
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(frame);
    bytes
}

fn pcapng_fixture(frame: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Section Header Block (little endian).
    bytes.extend_from_slice(&[0x0a, 0x0d, 0x0d, 0x0a]);
    bytes.extend_from_slice(&28u32.to_le_bytes());
    bytes.extend_from_slice(&[0x4d, 0x3c, 0x2b, 0x1a]);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&(-1i64).to_le_bytes());
    bytes.extend_from_slice(&28u32.to_le_bytes());

    // Interface Description Block: Ethernet, default microsecond resolution.
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&65535u32.to_le_bytes());
    bytes.extend_from_slice(&20u32.to_le_bytes());

    // Enhanced Packet Block.
    let padded_len = (frame.len() + 3) & !3;
    let block_len = 32 + padded_len;
    bytes.extend_from_slice(&6u32.to_le_bytes());
    bytes.extend_from_slice(&(block_len as u32).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // Interface ID.
    bytes.extend_from_slice(&0u32.to_le_bytes()); // Timestamp high.
    bytes.extend_from_slice(&1_500_000u32.to_le_bytes()); // Timestamp low.
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(frame);
    bytes.resize(bytes.len() + padded_len - frame.len(), 0);
    bytes.extend_from_slice(&(block_len as u32).to_le_bytes());
    bytes
}

fn ethernet_ipv4_udp_dns(query: &str) -> Vec<u8> {
    let mut dns = vec![0u8; 12];
    dns[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    dns[4..6].copy_from_slice(&1u16.to_be_bytes());
    for label in query.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());

    let udp_len = 8 + dns.len();
    let ip_len = 20 + udp_len;
    let mut frame = vec![0u8; 14 + ip_len];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut frame[14..34];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[192, 0, 2, 10]);
    ip[16..20].copy_from_slice(&[192, 0, 2, 53]);
    let udp = &mut frame[34..42];
    udp[0..2].copy_from_slice(&53000u16.to_be_bytes());
    udp[2..4].copy_from_slice(&53u16.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    frame[42..].copy_from_slice(&dns);
    frame
}

#[test]
fn extracts_dns_question_name_from_udp_query() {
    let capture = pcap_fixture(&ethernet_ipv4_udp_dns("Sub.Domain.Example"));
    let report = CaptureReader::read(Cursor::new(capture)).unwrap();
    assert_eq!(report.packets.len(), 1);
    assert_eq!(
        report.packets[0].dns_query_name.as_deref(),
        Some("sub.domain.example")
    );
}

#[test]
fn reads_classic_pcap_and_normalizes_tcp_metadata() {
    let report = CaptureReader::read(Cursor::new(pcap_fixture(&ethernet_ipv4_tcp()))).unwrap();
    assert_eq!(report.packets.len(), 1);
    assert_eq!(report.skipped_packets, 0);
    let packet = &report.packets[0];
    assert_eq!(packet.timestamp_ns, 7_500_000_000);
    assert_eq!(packet.source_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(packet.destination_port, Some(443));
    assert_eq!(packet.protocol, TransportProtocol::Tcp);
    assert_eq!(packet.tcp_flags, Some(0x02));
}

#[test]
fn streaming_visitor_matches_buffered_classic_pcap_results() {
    let capture = pcap_fixture(&ethernet_ipv4_tcp());
    let path = std::env::temp_dir().join(format!(
        "packethawk-streaming-{}.pcap",
        std::process::id()
    ));
    std::fs::write(&path, &capture).unwrap();

    let buffered = CaptureReader::read(Cursor::new(capture)).unwrap();
    let mut visited = Vec::new();
    let stats = CaptureReader::visit_path(&path, |packet| visited.push(packet)).unwrap();

    std::fs::remove_file(&path).unwrap();
    assert_eq!(visited, buffered.packets);
    assert_eq!(stats.decoded_packets, buffered.packets.len());
    assert_eq!(stats.skipped_packets, buffered.skipped_packets);
}

#[test]
fn streaming_visitor_counts_malformed_frames_without_panicking() {
    let capture = pcap_fixture(&[0u8; 8]);
    let path = std::env::temp_dir().join(format!(
        "packethawk-streaming-malformed-{}.pcap",
        std::process::id()
    ));
    std::fs::write(&path, capture).unwrap();

    let stats = CaptureReader::visit_path(&path, |_| {}).unwrap();

    std::fs::remove_file(&path).unwrap();
    assert_eq!(stats.decoded_packets, 0);
    assert_eq!(stats.skipped_packets, 1);
}

#[test]
fn reads_pcapng_enhanced_packet_block() {
    let report = CaptureReader::read(Cursor::new(pcapng_fixture(&ethernet_ipv4_tcp()))).unwrap();
    assert_eq!(report.packets.len(), 1);
    assert_eq!(report.packets[0].timestamp_ns, 1_500_000_000);
    assert_eq!(report.packets[0].destination_port, Some(443));
}

#[test]
fn malformed_frame_is_counted_and_does_not_panic() {
    let report = CaptureReader::read(Cursor::new(pcap_fixture(&[0u8; 8]))).unwrap();
    assert!(report.packets.is_empty());
    assert_eq!(report.skipped_packets, 1);
}

#[test]
fn rejects_truncated_capture_header() {
    let error = CaptureReader::read(Cursor::new(vec![0xd4, 0xc3, 0xb2, 0xa1])).unwrap_err();
    assert!(error.to_string().contains("truncated PCAP global header"));
}

#[test]
fn rejects_invalid_packet_length() {
    let mut capture = pcap_fixture(&ethernet_ipv4_tcp());
    capture[32..36].copy_from_slice(&9999u32.to_le_bytes());
    let error = CaptureReader::read(Cursor::new(capture)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid or truncated PCAP packet data")
    );
}

#[test]
fn recognizes_pcapng_and_reports_truncated_section() {
    let error = CaptureReader::read(Cursor::new(vec![0x0a, 0x0d, 0x0d, 0x0a])).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("truncated PCAPNG section header")
    );
}
