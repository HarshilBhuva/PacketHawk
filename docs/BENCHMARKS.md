# PacketHawk Benchmarks

## Suites

| Benchmark | Workload |
|---|---|
| `pcap_ingestion_20k_packets` | Parse a synthetic classic-PCAP capture containing 20,000 Ethernet/IPv4/TCP frames |
| `packet_analysis_10k/flow_aggregation/10k` | Aggregate 10,000 normalized packets into bounded bidirectional flows |
| `packet_analysis_10k/detection_engine/10k` | Run the batch detection engine over 10,000 normalized packets |

## Run locally

For a repeatable local report with toolchain, OS, CPU, commit, and three benchmark repetitions:

```bash
REPEATS=3 ./scripts/benchmark-report.sh
```

The script writes a timestamped report under `benchmark-results/`. Increase `REPEATS` for a more stable local sample. To run a single Criterion pass manually:

```bash
cargo bench --locked --bench ingestion -- --noplot
cargo bench --locked --bench analysis -- --noplot
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

## Initial CI observations (2026-11-25)

Two runs on the same hosted runner image and Rust toolchain produced the following Criterion estimates:

| Benchmark | Run A estimate | Run B estimate |
|---|---:|---:|
| PCAP ingestion, 20k packets | 1.9365 ms `[1.9345, 1.9386]` | 1.9941 ms `[1.9911, 1.9974]` |
| Flow aggregation, 10k packets | 5.9995 ms `[5.8015, 6.2024]` | 7.2890 ms `[7.1105, 7.4748]` |
| Batch detection, 10k packets | 5.0003 ms `[4.9928, 5.0107]` | 5.2616 ms `[5.2505, 5.2737]` |

- [Run A](https://github.com/HarshilBhuva/PacketHawk/actions/runs/45534318687)
- [Run B](https://github.com/HarshilBhuva/PacketHawk/actions/runs/45534480071)
- Both used GitHub-hosted `ubuntu-26.04` and Rust `1.100.0`.
- The workflow now prints CPU model, logical core count, OS, and Cargo/Rust versions for each benchmark run.

The flow aggregation spread between these two runs is large enough to demonstrate why these figures are **observations, not a release performance baseline**. The benchmark workflow now records CPU model and core information to improve future comparisons. Use a controlled, repeatable machine for release claims.

### Run C — environment captured

[Run C](https://github.com/HarshilBhuva/PacketHawk/actions/runs/45534783786) recorded the following environment:

- Ubuntu 26.04 hosted image.
- Rust/Cargo 1.100.0.
- AMD EPYC 9V45 96-Core Processor allocation; 2 cores, 4 logical CPUs.
- Criterion: 100 samples per benchmark.

| Benchmark | Estimate | Reported interval |
|---|---:|---:|
| PCAP ingestion, 20k packets | 1.4290 ms | 1.4264–1.4316 ms |
| Flow aggregation, 10k packets | 3.3235 ms | 3.2671–3.3843 ms |
| Batch detection, 10k packets | 3.0735 ms | 3.0692–3.0777 ms |

The hosted runner's observed numbers vary materially between runs even with the same OS image and compiler. These measurements document the benchmark harness and current order of magnitude; they are not suitable for cross-machine comparisons or a release throughput claim.
