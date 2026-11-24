# PacketHawk

**An offline-first network threat analysis engine written in Rust.**

PacketHawk is being built to inspect PCAP/PCAPNG captures, normalize packet metadata, reconstruct network flows, identify suspicious traffic patterns, and produce evidence-backed security alerts.

> **Development status:** Early development. The current foundation milestone establishes the Rust package, domain models, validated TOML configuration, and CI. PCAP ingestion and detection rules are not implemented yet.

## Planned capabilities

- PCAP and PCAPNG ingestion
- Ethernet, IPv4, IPv6, TCP, UDP, and DNS metadata extraction
- Directional and bidirectional flow analysis
- Vertical and horizontal port-scan heuristics
- DNS anomaly analysis
- Beaconing-like traffic detection
- Evidence-backed alerts with severity and confidence
- Terminal summaries and JSON reports
- Reproducible performance benchmarks

## Design principles

- **Offline first:** analyze existing captures without requiring privileged live capture.
- **Explainable detections:** every finding should include its rule, threshold, observed values, and supporting evidence.
- **Defensive use:** PacketHawk analyzes traffic and does not block, modify, or replay network traffic.
- **Bounded resource use:** large or malformed captures must not cause unbounded memory growth or panic.
- **Modular Rust:** parser, flow engine, detections, and reporting remain independently testable.

## Getting started

Install a stable Rust toolchain, then:

```bash
git clone https://github.com/HarshilBhuva/PacketHawk.git
cd PacketHawk
cargo build
cargo test
cargo run -- --help
```

Validate the example configuration:

```bash
cargo run -- config check config/default.toml
```

## Repository layout

```text
src/
  config.rs       TOML configuration and validation
  lib.rs          Reusable library entry point
  main.rs         CLI entry point
  models/         Parser-independent packet, flow, and alert models
config/           Default detection thresholds
docs/             Architecture and engineering documentation
tests/            Integration tests
.github/workflows/ Continuous integration
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
| M0 | Project foundation, models, configuration, CI | In progress |
| M1 | PCAP/PCAPNG ingestion and packet parsing | Planned |
| M2 | Flow aggregation and statistics | Planned |
| M3 | Port-scan, DNS, and beaconing detections | Planned |
| M4 | JSON reports, fixtures, and reliability hardening | Planned |
| M5 | Benchmarks, documentation, and v0.1.0 release | Planned |

## Limitations

Detection rules will be heuristic and can produce false positives. Findings are indicators for analyst review, not definitive attribution or proof of compromise. PacketHawk will document protocol coverage and parsing limitations as implementation progresses.

## License

MIT. See [LICENSE](LICENSE).
