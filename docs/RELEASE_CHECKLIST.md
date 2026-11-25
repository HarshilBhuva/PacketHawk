# v0.1.0 Release Checklist

This checklist records the completed v0.1.0 release gates and remaining post-publication verification.

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
- [x] Create the `v0.1.0` tag at the verified main-branch commit after CI passed.
- [x] Build the final release archive from the tagged commit with the committed lockfile.
- [x] Verify the archive checksum and extracted bundle in the release workflow before publication.
- [ ] Independently download the published archive and verify its SHA-256 checksum outside the release workflow.

## Post-publication verification

- The `v0.1.0` GitHub Release is published with the Linux x86_64 archive and `SHA256SUMS.txt`.
- The release workflow verified the archive checksum, extracted bundle, and CLI smoke tests before publishing.
- Independent download-and-checksum verification remains a separate recommended verification step.

## Release interpretation

The current CI validates formatting, Clippy, tests, benchmark compilation, stable release compilation, Rust 1.85 compatibility, dependency vulnerability scanning, license/source policy, and candidate archive checksum verification. The local benchmark is a machine-specific reference, not a universal throughput claim. The release workflow packages Linux x86_64 only; these checks do not prove cross-platform behavior or production readiness.
