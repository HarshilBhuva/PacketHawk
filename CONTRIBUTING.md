# Contributing to PacketHawk

## Development setup

1. Install the stable Rust toolchain with rustfmt and Clippy.
2. Clone the repository and enter the project directory.
3. Run `cargo build` before making changes.

## Before opening a pull request

Run all checks from the repository root:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
```

## Engineering expectations

- Keep packet parsing separate from domain models and detection rules.
- Treat capture files and configuration as untrusted input.
- Add tests for malformed and boundary-case inputs.
- Include evidence and observed values in detection results.
- Document protocol coverage and heuristic limitations.
- Do not claim performance improvements without reproducible benchmarks.

Keep pull requests focused. Prefer small changes that can be reviewed and validated independently.
