# Beaconing Detection

## Rule: NETWORK_BEACONING

PacketHawk groups TCP/UDP packets by source address, destination address, destination port, and transport protocol. It sorts capture timestamps and computes inter-arrival intervals.

For intervals (t_1, \ldots, t_n):

- Mean interval: \(\mu = \frac{1}{n}\sum t_i\)
- Population standard deviation: \(\sigma = \sqrt{\frac{1}{n}\sum (t_i-\mu)^2}\)
- Coefficient of variation: \(CV = \sigma/\mu\)

An alert is emitted when the conversation has at least `beacon_min_samples` packets and CV is at or below `beacon_max_interval_cv`. The default values are six packets and 0.15.

Severity is Medium by default and High when CV is at most half the configured maximum. Confidence is a bounded heuristic score based on how far below the configured CV threshold the observed CV falls.

## Evidence

Alerts include source/destination addresses, packet sample count, mean interval, interval standard deviation, observed CV, configured CV threshold, capture-time range, and transport protocol.

## Limitations

- This is timing-only analysis; it does not inspect application payloads.
- Zero inter-arrival intervals are excluded from detection to avoid divide-by-zero and duplicate-timestamp artifacts.
- Legitimate polling, monitoring, keep-alives, update agents, and scheduled jobs can be periodic.
- A low CV is not proof of command-and-control activity.
- The capture reader currently materializes packets in memory; streaming analysis is future work.
