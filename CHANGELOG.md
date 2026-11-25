# Changelog

All notable changes to PacketHawk are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

## [0.1.0] - 2026-11-25

### Added

- Rust CLI and validated TOML detection configuration.
- Offline classic PCAP and PCAPNG ingestion with bounded streaming readers.
- Ethernet II, VLAN, Linux cooked, IPv4/IPv6, TCP/UDP/ICMP metadata decoding.
- Bounded directional and bidirectional five-tuple flow aggregation with idle
  expiration and least-recently-seen eviction.
- Evidence-backed vertical and horizontal TCP/UDP port-scan indicators.
- Periodic TCP/UDP beacon-like traffic analysis using inter-arrival variation.
- UDP DNS question extraction and long/high-entropy query-name indicators.
- Human-readable and JSON output for capture inspection, flow summaries, and
  detection reports.
- Criterion benchmarks, CI security/dependency policies, and checksummed
  Linux x86_64 release packaging.

### Security

- Apply capture-file, packet-record, PCAPNG-block, and detector-state bounds.
- Handle malformed and truncated capture input without parser panics.
- Keep the initial product offline-only; no live capture, packet injection,
  active scanning, or traffic blocking.

### Known limitations

- IPv4 non-initial fragments and unsupported IPv6 extension-header chains are
  skipped; packet reassembly is not implemented.
- DNS-over-TCP, DoH, DoT, and other encrypted DNS payloads are not inspected.
- Detection results are heuristic investigative leads, not proof of compromise
  or calibrated probabilities.
- The published v0.1.0 binary archive targets Linux x86_64 only.
