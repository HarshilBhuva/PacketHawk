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

## Local reference run — Intel Celeron N4500 (2026-11-25)

A five-repeat local run was supplied from an Arch Linux x86_64 machine:

- CPU: Intel Celeron N4500, 2 cores / 2 threads, 1.10 GHz base (up to 2.80 GHz)
- OS/kernel: Arch Linux, Linux 7.3.4-arch1-2
- Rust/Cargo: 1.100.0
- Commit: `012ab70a3a587e70b10299f05de2da6ceb215a59`
- Criterion: 100 samples per benchmark in each of five invocations
- Working tree: clean

| Benchmark | Median estimate across 5 runs | Range of run estimates |
|---|---:|---:|
| PCAP ingestion, 20k packets | 2.2165 ms | 2.2109–2.5430 ms |
| Flow aggregation, 10k packets | 9.2343 ms | 9.1214–9.6743 ms |
| Batch detection, 10k packets | 8.1257 ms | 8.0116–8.2127 ms |

Approximate workload rates derived from the median estimates (not end-to-end application throughput):

- PCAP ingestion: 9.02 million packets/s
- Flow aggregation: 1.08 million normalized packets/s
- Batch detection: 1.23 million normalized packets/s

The ingestion suite's third run (2.5430 ms) is notably slower than its other four runs, while the analysis suites are more consistent. Keep the per-run data and Criterion intervals when investigating regressions; do not treat these derived rates as production throughput. This is a **machine-specific reference baseline**, not a cross-machine performance target. Re-run on the same machine, power profile, toolchain, and workload when comparing future changes.

The uploaded report was generated at `2026-11-25T05:27:53Z`. Its duplicate copy had the same SHA-256 and is not a second benchmark session.
