#!/usr/bin/env bash
set -euo pipefail

REPEATS="${REPEATS:-3}"
OUTPUT="${1:-benchmark-results/packethawk-benchmark-$(date -u +%Y%m%dT%H%M%SZ).log}"

if ! [[ "$REPEATS" =~ ^[1-9][0-9]*$ ]]; then
  echo "REPEATS must be a positive integer." >&2
  exit 2
fi

mkdir -p "$(dirname "$OUTPUT")"
exec > >(tee "$OUTPUT") 2>&1

echo "# PacketHawk benchmark report"
echo "Timestamp (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Commit: $(git rev-parse HEAD)"
echo "Working tree:"
git status --short || true
echo
echo "## Toolchain"
rustc --version --verbose
cargo --version
echo
echo "## Operating system and CPU"
uname -srmo
nproc
if command -v lscpu >/dev/null 2>&1; then
  lscpu
fi
echo
echo "## Criterion runs"
echo "Repeats: $REPEATS"

for run in $(seq 1 "$REPEATS"); do
  echo
  echo "### Run $run — PCAP ingestion"
  cargo bench --locked --bench ingestion -- --noplot --save-baseline "local-run-$run"

  echo
  echo "### Run $run — flow and detection analysis"
  cargo bench --locked --bench analysis -- --noplot --save-baseline "local-run-$run"
done

echo
echo "Report saved to: $OUTPUT"
sha256sum "$OUTPUT"
