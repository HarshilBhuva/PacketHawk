# v0.1.0 Release Checklist

This checklist is a release gate, not a statement that v0.1.0 is already published.

## Repository and dependency gates

- [x] Generate and commit `Cargo.lock` using the declared Rust toolchain.
- [x] Verify the lockfile and build with `cargo build --release --locked`.
- [x] Run cargo-audit 0.23.0 against the committed lockfile; no advisories reported for 99 dependencies on 2026-11-25.
- [x] Enforce dependency licenses and sources with `cargo deny check licenses bans sources`.
- [x] Confirm `rust-version = "1.85"` with the Rust 1.85.0 toolchain.
- [x] Review GitHub Actions permissions and pin third-party actions to immutable commit SHAs.

## Functional validation

- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo clippy --locked --all-targets --all-features -- -D warnings`.
- [x] Run `cargo test --locked --all-targets`.
- [x] Run `cargo bench --locked --no-run`.
- [x] Build the optimized binary with `cargo build --locked --release`.
- [x] Smoke-test `packethawk --version`, `packethawk --help`, and `config check`.
- [x] Validate classic PCAP/PCAPNG fixtures, malformed/truncated input, streaming detection, late packets, and state eviction.
- [x] Exercise documented CLI commands and human-readable/JSON output through binary-level integration tests.
- [x] Record a controlled, machine-specific reference benchmark (Intel Celeron N4500, Arch Linux x86_64, Rust 1.100.0; five repetitions on 2026-11-25). Results and interpretation are in [BENCHMARKS.md](BENCHMARKS.md). This is not a cross-machine performance target.

## Documentation and packaging

- [x] Add an unreleased changelog entry describing implemented capabilities and known limitations.
- [x] Review `SECURITY.md`, `README.md`, protocol coverage, and heuristic limitations.
- [x] Verify documented CLI examples against the binary through integration tests.
- [x] Build and checksum a non-release Linux x86_64 candidate artifact in CI; verify its checksum in the job.
- [ ] Build the final release archive from the tagged commit with the committed lockfile.
- [ ] Download the published archive and independently verify its SHA-256 checksum.
- [ ] Create the `v0.1.0` tag only after the main-branch CI and release-readiness PR are green.

## Current release blockers

- The tagged release archive has not yet been built or published.
- The published archive checksum has not yet been independently verified.
- The `v0.1.0` tag has not been created.

## Release interpretation

The current CI validates formatting, Clippy, tests, benchmark compilation, stable release compilation, Rust 1.85 compatibility, dependency vulnerability scanning, license/source policy, and candidate archive checksum verification. The local benchmark is a machine-specific reference, not a universal throughput claim. The release workflow packages Linux x86_64 only; these checks do not prove cross-platform behavior or production readiness.
