# Packet ingestion

## Data path

```text
PCAP / PCAPNG bytes
       |
       v
CaptureReader (size and block validation)
       |
       v
Link-layer decoder (Ethernet / VLAN / Linux SLL / raw IP)
       |
       v
IPv4 / IPv6 validation
       |
       v
TCP / UDP / ICMP metadata
       |
       v
NormalizedPacket
```

## Safety and behavior

- Input is limited to 512 MiB before parsing.
- All packet and block lengths are checked before slicing.
- Unknown PCAPNG blocks are skipped only after their block boundaries are validated.
- Unknown or unsupported link types return an explicit error.
- Malformed packet frames are counted in `CaptureReport::skipped_packets`; malformed capture structure is an error.
- IPv4 non-initial fragments and IPv6 extension-header chains are skipped. Reassembly is intentionally out of scope for this milestone.
- PCAPNG simple packet blocks have no timestamp; their normalized timestamp is zero.

## Public API

Use `packethawk::ingest::CaptureReader::read_path(path)` for files or
`CaptureReader::read(reader)` for any `Read` implementation. The result contains
normalized packets and a count of skipped packet frames.
