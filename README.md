# PacketHawk

**An offline-first network threat analysis engine written in Rust.**

PacketHawk inspects PCAP/PCAPNG captures, normalizes packet metadata, reconstructs network flows, identifies suspicious traffic patterns, and produces evidence-backed security alerts.

> **Development status:** M1 implements offline capture ingestion, packet decoding, and a basic capture-inspection CLI. Flow analysis and detection rules are not implemented yet.


## How PacketHawk works

PacketHawk is designed as an offline analysis pipeline. It starts with a saved capture, safely decodes supported network layers, and will progressively add flow context and explainable detection rules.

![PacketHawk architecture pipeline](docs/assets/packethawk-pipeline.svg)

### Analyst workflow

![PacketHawk investigation workflow](docs/assets/packethawk-workflow.svg)

## Current capabilities

- Read classic PCAP (little-/big-endian, microsecond/nanosecond timestamps).
- Read PCAPNG section, interface, enhanced packet, and simple packet blocks.
- Decode Ethernet II, up to two VLAN tags, Linux cooked capture, and raw IP link types.
- Extract IPv4/IPv6 addresses and TCP/UDP/ICMP metadata.
- Count unsupported or malformed packet frames without panicking.
- Cap input capture size at 512 MiB.
- Print a concise or JSON capture-ingestion summary.

## Getting started

Install a stable Rust toolchain, then:

```bash
git clone https://github.com/HarshilBhuva/PacketHawk.git
cd PacketHawk
cargo build
cargo test
cargo run -- --help
```

Inspect a capture:

```bash
cargo run -- capture inspect sample.pcap
cargo run -- capture inspect sample.pcapng --json
```

Validate the example configuration:

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
| M0 | Project foundation, models, configuration, CI | Complete in PR #1 |
| M1 | PCAP/PCAPNG ingestion and packet parsing | Implemented in this branch |
| M2 | Flow aggregation and statistics | Planned |
| M3 | Port-scan, DNS, and beaconing detections | Planned |
| M4 | JSON reports, fixtures, and reliability hardening | Planned |
| M5 | Benchmarks, documentation, and v0.1.0 release | Planned |

## Protocol coverage and limitations

The first parser supports Ethernet II (including up to two VLAN tags), Linux cooked capture, and raw IPv4/IPv6 link types. It extracts basic IPv4/IPv6 and TCP/UDP/ICMP metadata. IPv4 non-initial fragments and IPv6 extension-header chains are skipped rather than partially decoded. Unsupported link types are rejected. Packet-level parse failures are counted in the capture report; structural capture corruption returns an error.

Heuristic findings will be indicators for analyst review, not definitive attribution or proof of compromise.

## License

MIT. See [LICENSE](LICENSE).
