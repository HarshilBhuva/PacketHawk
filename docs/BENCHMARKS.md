# Benchmarks

PacketHawk uses Criterion to measure capture ingestion, flow aggregation, and
detection on deterministic synthetic workloads.

## Suites

| Benchmark | Workload |
|---|---|
| `pcap_ingestion_20k_packets` | Parse 20,000 synthetic Ethernet/IPv4/TCP frames |
| `packet_analysis_10k/flow_aggregation/10k` | Aggregate 10,000 normalized packets |
| `packet_analysis_10k/detection_engine/10k` | Run detection over 10,000 normalized packets |

## Run locally

Run the complete benchmark suite:

```bash
cargo bench --locked
```

Run an individual suite:

```bash
cargo bench --locked --bench ingestion -- --noplot
cargo bench --locked --bench analysis -- --noplot
```

Criterion writes detailed reports under `target/criterion/`.

## Interpreting results

- Compare runs only when hardware, operating system, Rust toolchain, and workload are equivalent.
- Repeat measurements and investigate regressions with profiling evidence.
- Hosted CI runners are variable; their results are useful for regression investigation, not as a stable cross-machine performance guarantee.
- Workload rates are not end-to-end application throughput claims.
