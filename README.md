# PacketHawk

**An offline-first network threat analysis engine written in Rust.**

PacketHawk inspects PCAP/PCAPNG captures, normalizes packet metadata, reconstructs network flows, identifies suspicious traffic patterns, and produces evidence-backed security alerts.

> **Release target:** `0.1.0` — offline PCAP/PCAPNG analysis with bounded streaming ingestion, flow aggregation, and evidence-backed detections.

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
- Stream both PCAP formats through the bounded detection engine, with explicit late-packet and state-eviction counters.

## Getting started

```bash
git clone https://github.com/HarshilBhuva/PacketHawk.git
cd PacketHawk
cargo build --locked
cargo test --locked
cargo run --locked -- --help
```

Inspect, aggregate, and detect:

```bash
cargo run -- capture inspect sample.pcap
cargo run -- capture flows sample.pcap --json
cargo run -- capture detect sample.pcap
cargo run -- capture detect sample.pcap --config config/default.toml --json
```

## Performance benchmarks

PacketHawk includes Criterion benchmarks for PCAP ingestion, flow aggregation, and the detection engine. They use deterministic synthetic data and are intended for before/after comparisons, not universal performance claims. See [the benchmark guide](docs/BENCHMARKS.md) for CI artifacts and interpretation.

```bash
REPEATS=3 ./scripts/benchmark-report.sh
```

## Development checks

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo bench --locked --no-run
cargo deny check licenses bans sources
cargo build --locked --release
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
| M8 | Streaming PCAPNG flow ingestion | Complete |
| M9 | Streaming detection pipeline and bounded detector state | Complete |
| M10 | v0.1.0 release hardening | Complete |
| M11 | License policy, immutable action pins, CI benchmark artifacts | Complete |
| M12 | Controlled benchmark baseline and v0.1.0 release | In progress |

## Detection interpretation

Port-scan rules use unique destination endpoints in capture-time sliding windows. Beaconing analysis groups TCP/UDP packets by source, destination, destination port, and transport protocol, then evaluates inter-arrival interval coefficient of variation. It requires the configured minimum sample count and ignores zero-length intervals.

A low coefficient of variation can also describe legitimate polling, monitoring, software updates, and persistent application sessions. Confidence is a heuristic score, not a calibrated probability. Alerts are investigative leads, not proof of compromise.

The flow and detection commands stream both classic PCAP and PCAPNG records. The detection engine ignores packets older than its maximum timestamp watermark and reports bounded-state evictions. DNS anomaly rules flag long or high-entropy DNS question names. DNS over TCP, DoH, DoT, and encrypted DNS payloads remain outside current parser coverage. No live capture, packet injection, blocking, or active scanning is performed.

## Benchmarks

PacketHawk includes Criterion suites for 20,000-packet PCAP ingestion, 10,000-packet flow aggregation, and 10,000-packet detection. See [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for commands and interpretation. CI stores Criterion reports as short-lived artifacts; they are not cross-machine performance guarantees.

## Security and release status

PacketHawk is an early-stage defensive analysis tool. Review [SECURITY.md](SECURITY.md) before reporting vulnerabilities and [the release checklist](docs/RELEASE_CHECKLIST.md) for current v0.1.0 release gates. No stable release has been published yet.

## License

MIT. See [LICENSE](LICENSE).
