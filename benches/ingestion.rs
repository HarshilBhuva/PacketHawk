use std::io::Cursor;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use packethawk::ingest::CaptureReader;

fn ethernet_ipv4_tcp() -> Vec<u8> {
    let mut frame = vec![0u8; 54];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut frame[14..34];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&40u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&[192, 0, 2, 10]);
    ip[16..20].copy_from_slice(&[198, 51, 100, 20]);
    let tcp = &mut frame[34..54];
    tcp[0..2].copy_from_slice(&50000u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x10;
    frame
}

fn synthetic_pcap(packet_count: usize) -> Vec<u8> {
    let frame = ethernet_ipv4_tcp();
    let mut capture = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,
    ];
    for index in 0..packet_count {
        capture.extend_from_slice(&(index as u32).to_le_bytes());
        capture.extend_from_slice(&0u32.to_le_bytes());
        capture.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        capture.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        capture.extend_from_slice(&frame);
    }
    capture
}

fn benchmark_ingestion(c: &mut Criterion) {
    let capture = synthetic_pcap(20_000);
    c.bench_function("pcap_ingestion_20k_packets", |b| {
        b.iter(|| {
            let mut reader = Cursor::new(black_box(&capture));
            black_box(CaptureReader::read(&mut reader).expect("synthetic PCAP is valid"));
        });
    });
}

criterion_group!(benches, benchmark_ingestion);
criterion_main!(benches);
