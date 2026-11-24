use std::net::{IpAddr, Ipv4Addr};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use packethawk::{
    config::DetectionConfig,
    detection::DetectionEngine,
    flow::{FlowAggregator, FlowConfig, FlowDirection},
    models::{NormalizedPacket, TransportProtocol},
};

fn synthetic_packets(count: usize) -> Vec<NormalizedPacket> {
    (0..count)
        .map(|index| NormalizedPacket {
            timestamp_ns: (index as u128) * 1_000_000,
            source_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, (index % 16 + 1) as u8)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(
                198,
                51,
                100,
                (index % 64 + 1) as u8,
            )),
            source_port: Some(40_000 + (index % 1000) as u16),
            destination_port: Some(443 + (index % 50) as u16),
            protocol: TransportProtocol::Tcp,
            packet_size: 96,
            tcp_flags: Some(0x10),
            dns_query_name: None,
        })
        .collect()
}

fn benchmark_analysis(c: &mut Criterion) {
    let packets = synthetic_packets(10_000);
    let flow_config = FlowConfig {
        max_active_flows: 50_000,
        idle_timeout_ns: 120_000_000_000,
        direction: FlowDirection::Bidirectional,
    };
    let detection_config = DetectionConfig::default();
    let mut group = c.benchmark_group("packet_analysis_10k");

    group.bench_function(BenchmarkId::new("flow_aggregation", "10k"), |b| {
        b.iter(|| {
            let mut aggregator = FlowAggregator::new(flow_config.clone()).unwrap();
            for packet in black_box(&packets) {
                aggregator.observe(packet);
            }
            black_box(aggregator.report());
        });
    });

    group.bench_function(BenchmarkId::new("detection_engine", "10k"), |b| {
        b.iter(|| {
            black_box(DetectionEngine::new(detection_config.clone()).analyze(black_box(&packets)));
        });
    });
    group.finish();
}

criterion_group!(benches, benchmark_analysis);
criterion_main!(benches);
