# PacketHawk

**An offline-first network threat analysis engine written in Rust.**

PacketHawk inspects PCAP/PCAPNG captures, normalizes packet metadata, reconstructs network flows, identifies suspicious traffic patterns, and produces evidence-backed security alerts.

> **Development status:** M3 adds explainable vertical and horizontal TCP/UDP port-scan heuristics on top of bounded flow aggregation.

## How PacketHawk works

PacketHawk is designed as an offline analysis pipeline. It starts with a saved capture, safely decodes supported network layers, builds bounded bidirectional or directional flow records, and evaluates explainable detection rules.

![PacketHawk architecture pipeline](docs/assets/packethawk-pipeline.svg)

### Analyst workflow

![PacketHawk investigation workflow](docs/assets/packethawk-workflow.svg)

## Current capabilities

- Read classic PCAP and PCAPNG captures.
- Decode Ethernet II, VLAN, Linux cooked, and supported raw IP frames.
- Extract IPv4/IPv6 addresses and TCP/UDP/ICMP metadata.
- Count malformed packet frames without panicking and cap input at 512 MiB.
- Inspect captures with concise or JSON summaries.
- Aggregate bounded directional or bidirectional five-tuple flows.
- Track packet/byte counters, direction, first/last seen timestamps, and duration.
- Expire idle flows and evict the least-recently-seen flow at configured capacity.
- Detect vertical port scans (one source to many ports on one host).
- Detect horizontal port scans (one source to one service port across many hosts).
- Emit evidence-backed alerts with severity, confidence, observed values, and thresholds.

## Getting started

```bash
git clone https://github.com/HarshilBhuva/PacketHawk.git
cd PacketHawk
cargo build
cargo test
cargo run -- --help
```

Inspect and summarize:

```bash
cargo run -- capture inspect sample.pcap
cargo run -- capture flows sample.pcap --json
```

Run port-scan detections:

```bash
cargo run -- capture detect sample.pcap
cargo run -- capture detect sample.pcap --config config/default.toml --json
```

Validate configuration:

```bash
cargo run -- config check config/default.toml
```

## Development checks

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
```

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| M0 | Foundation, models, configuration, CI | Complete |
| M1 | Offline PCAP/PCAPNG ingestion | Complete |
| M2 | Bounded flow aggregation | Complete |
| M3 | Vertical and horizontal port-scan detections | Implemented in this branch |
| M4 | DNS anomalies and beaconing detections | Next |
| M5 | Streaming, benchmarks, and v0.1.0 release hardening | Planned |

## Detection interpretation

Port-scan rules are threshold-based heuristics over TCP/UDP packets. A vertical scan counts unique destination ports for one source/destination-host pair; a horizontal scan counts unique destination hosts for one source/destination-port pair. Windows use capture timestamps and are evaluated per source. Retransmissions to the same endpoint do not inflate unique counts. Input packets are timestamp-sorted before evaluation.

Alerts contain the observed endpoint set, configured threshold, time window, severity, and a heuristic confidence score. These detections are investigative leads, not proof of compromise. The current capture reader materializes decoded packets before analysis; streaming ingestion and DNS/beaconing rules remain future work.

## Limitations

No live capture, packet injection, blocking, TCP stream reassembly, IP fragment reassembly, or application-layer session reconstruction. IPv4 non-initial fragments and IPv6 extension-header chains are skipped rather than partially decoded.

## License

MIT. See [LICENSE](LICENSE).
