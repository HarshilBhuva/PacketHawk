# PacketHawk Architecture

## Goals

PacketHawk is an offline-first network traffic analysis tool. It separates capture I/O, protocol parsing, normalized domain models, flow aggregation, detection, and reporting so each layer can be tested independently.

## Planned data path

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
Flow Aggregator
     |
     v
NetworkFlow + Packet Evidence
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

- `capture`: capture-file reading, timestamps, link-layer metadata, and truncation handling.
- `parser`: safe decoding of supported protocol headers.
- `models`: parser-independent packet, flow, and alert types.
- `flow`: flow identity, aggregation, counters, and time windows.
- `detection`: independent, configurable detection rules.
- `reporting`: human-readable summaries and machine-readable output.
- `config`: validated user configuration.
- `cli`: command-line interface and application orchestration.

## Domain model decisions

- IP addresses use `std::net::IpAddr`, not free-form strings.
- Ports are optional because not every packet is TCP or UDP.
- Packet timestamps are represented as nanoseconds from the Unix epoch.
- Flow keys are directional five-tuples in the initial model. Bidirectional conversation grouping will be an explicit aggregation policy rather than an implicit key mutation.
- Alerts carry evidence and confidence. Confidence is not equivalent to probability unless a calibrated statistical model is introduced.

## Reliability requirements

- Treat all capture contents as untrusted input.
- Distinguish truncated packets from malformed packets.
- Never panic on a malformed frame.
- Bound memory use and expose capture-processing limits.
- Preserve enough packet/flow references to reproduce why an alert fired.
- Make rule thresholds configurable and document false-positive limitations.

## Current implementation status

The initial foundation provides domain models and validated TOML configuration. Capture reading, packet parsing, aggregation, detections, and reports remain future milestones.
