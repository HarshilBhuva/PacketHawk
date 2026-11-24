# Flow Aggregation

PacketHawk converts decoded NormalizedPacket records into bounded NetworkFlow records.

## Identity

A flow key contains source IP, destination IP, source port, destination port, and transport protocol.

- **Bidirectional (default):** endpoint tuples are sorted to produce a stable conversation key. Counters preserve which direction each packet travelled.
- **Directional:** source-to-destination ordering is retained, producing separate records for each direction.

## Counters and timestamps

Each flow tracks total packets/bytes, forward and reverse packet/byte counters, first-seen timestamp, and last-seen timestamp. Duration is last_seen_ns - first_seen_ns. Out-of-order packet timestamps update the earliest timestamp without moving last-seen time backwards.

Counters use saturating arithmetic.

## Bounded state

The active table uses a hash map for key lookup and a sorted recency index for maintenance. The default capacity is 100,000 active flows; the default idle timeout is 120 seconds. When the capture timestamp watermark advances, entries idle for at least the configured timeout are expired. When capacity is reached, the least-recently-seen flow is evicted before a new flow is inserted.

The flow table itself is bounded. The current capture reader still materializes the decoded packet list before aggregation; streaming ingestion is a separate future optimization.

## CLI

```bash
packethawk capture flows sample.pcap
packethawk capture flows sample.pcap --max-active-flows 50000 --idle-timeout-secs 90
packethawk capture flows sample.pcap --directional --json
```

JSON output contains the flow records and run counters. Text output summarizes the run and lists the ten largest flows by observed bytes.

## Non-goals

This milestone does not perform TCP stream reassembly, IP fragment reassembly, application protocol reconstruction, live capture, or detection. Flow aggregation provides context for later rules; it does not label a flow as malicious.
