# Changelog

All notable user-visible changes to PacketHawk are documented here.

## [Unreleased]

### Added
- Offline classic PCAP and PCAPNG ingestion with bounded input, packet, and block sizes.
- Incremental PCAP/PCAPNG traversal for flow aggregation and packet-level detection.
- Directional and bidirectional flow aggregation with bounded state and idle expiry.
- Evidence-backed vertical and horizontal port-scan, periodic beaconing, and DNS query anomaly detections.
- Streaming detection counters for late packets and detector-state evictions.
- Criterion benchmarks for ingestion, flow aggregation, and detection, with CI report artifacts.
- Immutable SHA-pinned GitHub Actions and dependency license/source policy checks.

### Security and reliability
- Malformed and truncated capture data is validated without panicking.
- Per-source scan windows, beacon conversation state, and DNS deduplication are bounded.
- Streaming detections report timestamp-ordering drops and state evictions.

### Known limitations
- Streaming detection ignores packets older than the maximum timestamp watermark.
- Detector-state eviction can reduce coverage on very large or high-cardinality captures.
- DNS parsing is limited to UDP DNS question names; DoH, DoT, encrypted DNS, and DNS-over-TCP are not analyzed.
- IPv4 non-initial fragments and IPv6 extension-header chains are not reassembled.
- No live capture, packet injection, active scanning, blocking, or automated response.
