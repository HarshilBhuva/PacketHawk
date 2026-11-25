# PacketHawk Benchmarks

## Suites

| Benchmark | Workload |
|---|---|
| `pcap_ingestion_20k_packets` | Parse a synthetic classic-PCAP capture containing 20,000 Ethernet/IPv4/TCP frames |
| `packet_analysis_10k/flow_aggregation/10k` | Aggregate 10,000 normalized packets into bounded bidirectional flows |
| `packet_analysis_10k/detection_engine/10k` | Run the batch detection engine over 10,000 normalized packets |

## Run locally

```bash
cargo bench --locked -- --noplot
```

Criterion reports are written to `target/criterion/`. To compare a local change against a named baseline:

```bash
cargo bench --locked -- --save-baseline before
# Apply the change.
cargo bench --locked -- --baseline before
```

## CI artifacts

The CI benchmark job runs the same suites on GitHub-hosted `ubuntu-latest` runners and uploads the Criterion reports as a 14-day artifact named `packethawk-criterion-<commit-sha>`. The runner CPU, virtualization, load, and image can change; use these artifacts for regression investigation, not as a stable cross-machine performance guarantee.

## Interpretation

- Compare results only when the runner image, architecture, Rust toolchain, and benchmark workload are equivalent.
- Investigate regressions with repeated runs and profiler evidence.
- Do not treat one noisy CI run as a release-blocking performance regression.
- No absolute throughput target is claimed until a controlled reference environment and repeatable baseline are established.
