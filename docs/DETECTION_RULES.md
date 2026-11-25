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


## DNS_QUERY_ANOMALY

The capture decoder extracts the first question name from UDP DNS packets on port 53. It validates DNS headers, label lengths, compression pointers, pointer depth, and the 253-byte wire-name limit. The detector flags names exceeding the configured length threshold or Shannon-entropy threshold and deduplicates identical source/query pairs per capture analysis.

DNS over TCP, DoH, DoT, encrypted DNS, DNS response correlation, and multi-question analysis are not implemented. Long or high-entropy names can be legitimate; findings are triage indicators, not malicious-domain verdicts.

## Streaming behavior and resource bounds

The streaming detection engine expects capture timestamps to be nondecreasing. Packets older than the maximum timestamp watermark are ignored and counted. Detector state is bounded: port-scan windows cap source trackers and retained events, beaconing caps active conversations, and DNS deduplication uses a bounded FIFO cache. When a limit is reached, old state is evicted; eviction counts are included in the report. State eviction can reduce detection coverage and should be reviewed alongside alerts.
