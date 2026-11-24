# Detection Rules

## PORT_SCAN_VERTICAL

One source contacts at least `port_scan_unique_ports` distinct TCP/UDP destination ports on one destination host within `scan_window_secs`.

Evidence includes the source and destination addresses, observed destination ports, capture-time window, and configured threshold. Repeated packets to one port do not increase the unique-port count.

## PORT_SCAN_HORIZONTAL

One source contacts at least `horizontal_scan_unique_hosts` distinct destination hosts on one TCP/UDP service port within `scan_window_secs`.

Evidence includes source address, destination port, observed destination hosts, capture-time window, and configured threshold.

## Alert interpretation

Severity increases when the observed unique endpoint count reaches at least twice the configured threshold. Confidence is a bounded heuristic score based on the observed-to-threshold ratio; it is not a calibrated probability.

Legitimate inventory scans, vulnerability scanners, monitoring systems, and application retries can produce these patterns. Alerts are investigative leads, not proof of compromise.

## Planned rules

- DNS query anomalies: excessive query length and high-entropy labels (requires DNS parsing).
- Network beaconing: regular inter-arrival intervals for repeated destination conversations.


## NETWORK_BEACONING

The beaconing detector groups TCP/UDP packets by source IP, destination IP, destination port, and protocol. It sorts timestamps, calculates inter-arrival intervals, and flags conversations with enough intervals and a coefficient of variation at or below the configured maximum. Conversation count and retained timestamps are bounded.

Periodic traffic can be legitimate. Beaconing findings require process-level, destination reputation, and threat-intelligence context before escalation.
