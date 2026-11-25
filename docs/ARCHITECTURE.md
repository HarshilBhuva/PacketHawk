# PacketHawk Architecture

## Goals

PacketHawk is an offline-first network traffic analysis tool. It separates capture I/O, protocol parsing, normalized domain models, flow aggregation, detection, and reporting so each layer can be tested independently.

## Data path

```text
PCAP / PCAPNG
     |
     v
Capture Reader
     |
     v
Link + Network + Transport Parsing
     |
     v
NormalizedPacket
     |
     v
Bounded Flow Aggregator
     |
     v
NetworkFlow + Directional Counters
     |
     v
Detection Engine
     |
     v
SecurityAlert
     |
     v
Terminal / JSON Reports
```

## Module boundaries

- `ingest`: capture-file reading, timestamps, link-layer metadata, and safe packet decoding. Classic-PCAP flow analysis has a visitor API that decodes one record at a time; PCAPNG remains buffered pending a block-streaming parser.
- `models`: parser-independent packet, flow, and alert types.
- `flow`: flow identity, bidirectional/directional aggregation, counters, expiry, and eviction.
- `detection`: independent, configurable detection rules (next milestone).
- `config`: validated user configuration.
- `cli`: command-line interface and application orchestration.

## Domain model decisions

- IP addresses use `std::net::IpAddr`, not free-form strings.
- Ports are optional because not every packet is TCP or UDP.
- Packet timestamps are represented as nanoseconds from the Unix epoch.
- Bidirectional flow keys canonicalize endpoint ordering; forward/reverse counters retain packet direction.
- Directional mode preserves the source-to-destination five-tuple as the key.
- Flow duration is the difference between earliest and latest observed timestamps.
- Flow confidence is not inferred at the aggregation layer; detection rules must provide their own evidence and rationale.

## Resource and reliability requirements

- Treat all capture contents as untrusted input.
- Bound capture input and active flow state.
- Use a hash map for flow lookup and an ordered recency index for expiry/eviction.
- Expire flows using a maximum observed timestamp watermark so out-of-order timestamps do not move recency backwards.
- Evict the least-recently-seen flow when the configured active-flow capacity is reached.
- Use saturating counters to avoid integer overflow in long captures.
- Never panic on malformed frames.

## Current implementation status

M0 foundation, M1 offline capture ingestion, M2 bounded flow aggregation, and the port-scan, DNS, and beaconing detection rules are implemented. M7 introduces record-at-a-time classic-PCAP flow ingestion; PCAPNG and the detection pipeline still use the buffered compatibility path.
