# v0.1.0 Release Checklist

This checklist is a release gate, not a statement that v0.1.0 is ready.

## Repository and dependency gates

- [x] Generate and commit `Cargo.lock` using the declared Rust toolchain.
- [x] Verify the lockfile is reviewed and the build passes with `cargo build --release --locked`.
- [x] Run a dependency vulnerability audit against the committed lockfile (cargo-audit 0.23.0; no advisories reported for 99 dependencies on 2026-11-25).
- [x] Review dependency licenses and enforce the allow-list with `cargo deny check licenses bans sources` (current graph uses Apache-2.0, MIT, Unicode-3.0, and Unlicense).
- [x] Confirm `rust-version = "1.85"` against an actual Rust 1.85.0 toolchain build.
- [x] Review GitHub Actions permissions and pin third-party actions to immutable commit SHAs; Dependabot tracks action updates.

## Functional validation

- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo clippy --locked --all-targets --all-features -- -D warnings`.
- [x] Run `cargo test --locked --all-targets`.
- [x] Run `cargo bench --locked --no-run`.
- [x] Run `cargo build --locked --release`.
- [x] Smoke-test `packethawk --version`, `packethawk --help`, and `config check`.
- [x] Validate classic PCAP and PCAPNG fixtures, including malformed/truncated input.
- [x] Validate streaming detection with ordered timestamps, late packets, and state eviction.
- [ ] Record benchmark baselines from a controlled reference environment; CI Criterion artifacts are available but are not a stable hardware baseline.

## Documentation and packaging

- [ ] Update `CHANGELOG.md` with the exact release contents.
- [x] Review `SECURITY.md`, `README.md`, protocol coverage, and heuristic limitations.
- [ ] Confirm CLI examples match the released binary.
- [x] Build and checksum a non-release Linux x86_64 candidate artifact in CI; verify its checksum in the job.
- [ ] Build the final release artifact from the tagged commit with the committed lockfile.
- [ ] Download the tagged artifact and verify its SHA-256 checksum.
- [ ] Create the `v0.1.0` tag only after every required gate passes.

## Current release blockers

- Controlled reference-machine benchmark baselines remain outstanding.
- No tagged release artifact or SHA-256 verification has been published.
- The changelog still needs a final `0.1.0` entry immediately before tagging.

## Release interpretation

The current CI proves formatting, Clippy, tests, benchmark compilation, stable release compilation, Rust 1.85 compatibility, dependency vulnerability scanning, license/source policy, and candidate archive checksum verification. CI benchmark artifacts are diagnostic, not a controlled reference baseline. The release workflow currently packages Linux x86_64 only; these checks do not prove cross-platform behavior or production readiness.
