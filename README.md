# PacketHawk

**An offline-first network threat analysis engine written in Rust.**

PacketHawk inspects PCAP/PCAPNG captures, normalizes packet metadata, reconstructs network flows, identifies suspicious traffic patterns, and produces evidence-backed security alerts.

> **Development status:** M4 adds periodic-traffic beaconing heuristics alongside vertical and horizontal port-scan detection.

## How PacketHawk works

PacketHawk analyzes saved captures through a bounded ingestion, decoding, flow, and detection pipeline.

![PacketHawk architecture pipeline](docs/assets/packethawk-pipeline.svg)

### Analyst workflow

![PacketHawk investigation workflow](docs/assets/packethawk-workflow.svg)

## Current capabilities

- Read classic PCAP and PCAPNG captures.
- Stream classic-PCAP records and PCAPNG blocks incrementally into flow aggregation without retaining the full decoded packet list.
- Enforce a 16 MiB per-packet record cap and 16 MiB + 4 KiB PCAPNG block cap, in addition to the 512 MiB capture-file cap.
- Decode supported Ethernet, VLAN, Linux cooked, IPv4/IPv6, TCP/UDP/ICMP metadata.
- Count malformed packet frames without panicking and cap input at 512 MiB.
- Aggregate bounded directional or bidirectional five-tuple flows.
- Track packet/byte counters, direction, first/last seen timestamps, and duration.
- Expire idle flows and evict least-recently-seen flows at configured capacity.
- Detect vertical TCP/UDP port scans across destination ports.
- Detect horizontal TCP/UDP scans across destination hosts.
- Detect regular periodic TCP/UDP conversations using inter-arrival coefficient of variation.
- Extract DNS question names from UDP DNS queries and flag long or high-entropy names.
- Emit evidence-backed alerts with severity, heuristic confidence, observed values, and thresholds.

## Getting started

```bash
git clone https://github.com/HarshilBhuva/PacketHawk.git
cd PacketHawk
cargo build
cargo test
cargo run -- --help
```

Inspect, aggregate, and detect:

```bash
cargo run -- capture inspect sample.pcap
cargo run -- capture flows sample.pcap --json
cargo run -- capture detect sample.pcap
cargo run -- capture detect sample.pcap --config config/default.toml --json
```

## Performance benchmarks

PacketHawk includes Criterion benchmarks for PCAP ingestion, flow aggregation, and the detection engine. They use deterministic synthetic data and are intended for before/after comparisons, not universal performance claims.

```bash
cargo bench --bench ingestion
cargo bench --bench analysis
```

## Development checks

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo bench --no-run
cargo build --release
```

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M0 | Foundation, models, configuration, CI | Complete |
| M1 | Offline PCAP/PCAPNG ingestion | Complete |
| M2 | Bounded flow aggregation | Complete |
| M3 | Vertical and horizontal port-scan detections | Complete |
| M4 | Port-scan and periodic beaconing detections | Complete |
| M5 | DNS query parsing and anomaly detection | Complete |
| M6 | Reproducible ingestion and analysis benchmarks | Complete |
| M7 | Streaming classic-PCAP flow ingestion | Complete |
| M8 | Streaming PCAPNG flow ingestion | Implemented in this branch |
| M9 | Streaming detection pipeline and v0.1.0 release hardening | Planned |

## Detection interpretation

Port-scan rules use unique destination endpoints in capture-time sliding windows. Beaconing analysis groups TCP/UDP packets by source, destination, destination port, and transport protocol, then evaluates inter-arrival interval coefficient of variation. It requires the configured minimum sample count and ignores zero-length intervals.

A low coefficient of variation can also describe legitimate polling, monitoring, software updates, and persistent application sessions. Confidence is a heuristic score, not a calibrated probability. Alerts are investigative leads, not proof of compromise.

The detection command still materializes decoded packets before analysis; flow aggregation streams both classic PCAP and PCAPNG records. DNS anomaly rules flag long or high-entropy DNS question names. DNS over TCP, DoH, DoT, and encrypted DNS payloads remain outside current parser coverage. No live capture, packet injection, blocking, or active scanning is performed.

## License

MIT. See [LICENSE](LICENSE).
