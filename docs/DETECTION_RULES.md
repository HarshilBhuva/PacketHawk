# Detection Rules

## PORT_SCAN_VERTICAL

Detects one source contacting multiple unique destination ports on one destination host within the configured time window. Evidence includes source and destination IPs, unique port count, threshold, window duration, and a bounded sample of observed ports.

## PORT_SCAN_HORIZONTAL

Detects one source contacting the same destination service port across multiple unique destination hosts within the configured time window. Evidence includes source IP, destination port, unique host count, threshold, window duration, and a bounded host sample.

## State and reliability

- Only TCP/UDP packets with decoded source and destination ports are considered.
- A maximum-timestamp watermark prevents out-of-order timestamps from moving the window backwards; packets arriving outside the current window are ignored.
- Each tracker retains at most 4,096 unique targets.
- Total tracker count is bounded by the caller-provided capacity; the least-recently-updated tracker is evicted when full.
- A rule alerts once per threshold crossing and can alert again after its target set expires.
- DNS anomaly and beaconing rules are not implemented yet.

## Interpretation

These heuristics are investigative indicators, not proof of malicious activity. Vulnerability scanners, service discovery, inventory agents, and monitoring systems can produce similar patterns. Tune thresholds to local traffic baselines.
