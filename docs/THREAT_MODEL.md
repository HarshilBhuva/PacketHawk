# PacketHawk Threat Model

## Assets

- Analyst workstation and local capture files
- Packet metadata and derived flow records
- Detection configuration
- Investigation reports and alert evidence

## Trust boundaries

PCAP and PCAPNG files are untrusted input. They may be truncated, malformed, deliberately crafted, or extremely large. Configuration files are also untrusted input and must be parsed and validated.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Malformed packet causes panic | Bounds-checked parsing and malformed-input tests |
| Crafted capture exhausts memory | Streaming ingestion and configurable resource limits |
| Corrupt timestamps distort detections | Validate and normalize timestamps |
| False positive is treated as fact | Explainable evidence and heuristic disclaimers |
| Sensitive payload is unnecessarily retained | Prefer metadata-only processing; avoid payload persistence by default |
| Malicious config disables useful checks | Validate ranges and provide safe defaults |

## Out of scope for the first release

- Live packet capture
- Packet injection or replay
- Active blocking or firewall modification
- Payload decryption
- Automated attribution
- Autonomous incident response

PacketHawk is a defensive analysis utility. Analysts remain responsible for interpreting findings.
