# Contributing to PacketHawk

## Development setup

1. Install the stable Rust toolchain with rustfmt and Clippy.
2. Clone the repository and enter the project directory.
3. Run `cargo build` before making changes.

## Before opening a pull request

Run all checks from the repository root:

```bash
cargo fmt --all
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo bench --locked --no-run
cargo deny check licenses bans sources
cargo audit
cargo build --locked --release
./target/release/packethawk --version
./target/release/packethawk config check config/default.toml
```

## Engineering expectations

- Keep packet parsing separate from domain models and detection rules.
- Treat capture files and configuration as untrusted input.
- Add tests for malformed and boundary-case inputs.
- Include evidence and observed values in detection results.
- Document protocol coverage and heuristic limitations.
- Do not claim performance improvements without reproducible benchmarks.

Keep pull requests focused. Prefer small changes that can be reviewed and validated independently.

## Release changes

- Update `CHANGELOG.md` for user-visible behavior.
- Do not create a version tag until every item in `docs/RELEASE_CHECKLIST.md` is satisfied.
- Commit and review `Cargo.lock` before any reproducible release build.
- Keep the documented parser coverage, timestamp-ordering policy, and detector state limits synchronized with implementation.
