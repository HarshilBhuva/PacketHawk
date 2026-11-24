# Performance Benchmarks

## What is measured

- **PCAP ingestion:** parse a deterministic classic-PCAP fixture containing 20,000 Ethernet/IPv4/TCP packets.
- **Flow aggregation:** build bounded bidirectional five-tuple state from 10,000 normalized TCP packets.
- **Detection engine:** run port-scan and beaconing analysis over the same 10,000-packet synthetic workload.

## Run locally

```bash
cargo bench --bench ingestion
cargo bench --bench analysis
```

Criterion stores local measurements under `target/criterion`. Keep the toolchain, machine, power profile, and benchmark parameters consistent when comparing commits. Use multiple runs and compare distributions rather than relying on a single sample.

## CI policy

CI compiles all benchmark targets with `cargo bench --no-run`. It does not enforce timing thresholds because shared CI runners have noisy and variable performance. Performance claims should cite the machine, toolchain, workload size, and raw Criterion output.

## Limitations

These are synthetic microbenchmarks. They do not represent every PCAP link type, capture size, production traffic mix, or storage device. Streaming ingestion and peak-memory measurements remain separate future work.
