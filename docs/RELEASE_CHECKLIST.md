# v0.1.0 Release Checklist

This checklist is a release gate, not a statement that v0.1.0 is ready.

## Repository and dependency gates

- [ ] Generate and commit `Cargo.lock` using the declared Rust toolchain.
- [ ] Verify the lockfile is reviewed and the build passes with `cargo build --release --locked`.
- [ ] Run a dependency vulnerability audit against the committed lockfile.
- [ ] Review dependency licenses and update policy.
- [ ] Confirm `rust-version = "1.85"` against an actual Rust 1.85 toolchain build.
- [ ] Review GitHub Actions permissions and pin/update third-party actions deliberately.

## Functional validation

- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy --all-targets --all-features -- -D warnings`.
- [ ] Run `cargo test --all-targets`.
- [ ] Run `cargo bench --no-run`.
- [ ] Run `cargo build --release`.
- [ ] Smoke-test `packethawk --version`, `packethawk --help`, and `config check`.
- [ ] Validate classic PCAP and PCAPNG fixtures, including malformed/truncated input.
- [ ] Validate streaming detection with ordered timestamps, late packets, and state eviction.
- [ ] Record benchmark baselines and environment details; do not publish unsupported performance claims.

## Documentation and packaging

- [ ] Update `CHANGELOG.md` with the exact release contents.
- [ ] Review `SECURITY.md`, `README.md`, protocol coverage, and heuristic limitations.
- [ ] Confirm CLI examples match the released binary.
- [ ] Build the release artifact from the tagged commit with the committed lockfile.
- [ ] Generate SHA-256 checksums and verify the downloaded artifact.
- [ ] Create the `v0.1.0` tag only after every required gate passes.

## Current release blockers

- `Cargo.lock` is not currently committed. The release workflow intentionally refuses to publish without it.
- A dependency vulnerability audit and a Rust 1.85 toolchain validation have not yet been recorded.
- No release artifact or benchmark baseline has been published.

## Release interpretation

The current CI proves formatting, Clippy, tests, benchmark compilation, and stable release compilation. It does not by itself prove dependency vulnerability status, reproducible dependency resolution, cross-platform behavior, or production readiness.
