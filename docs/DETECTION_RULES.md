# Detection Rules

This document defines the intended first-release heuristics. Thresholds are starting defaults and must remain configurable.

## PORT_SCAN_VERTICAL

One source contacts an unusually large number of distinct destination ports on one destination host within a configured time window.

Evidence should include source and destination addresses, observed destination ports, time window, threshold, and packet/flow references.

## PORT_SCAN_HORIZONTAL

One source contacts the same destination service port across an unusually large number of destination hosts within a configured time window.

Evidence should include source address, destination port, unique destination hosts, time window, and threshold.

## DNS_QUERY_ANOMALY

A source generates DNS query names that exceed configured length or entropy heuristics. Long or high-entropy names can occur in legitimate applications, CDNs, and tracking systems; the rule must not label a domain malicious solely on this basis.

## NETWORK_BEACONING

A source repeatedly contacts the same destination with sufficiently regular inter-arrival intervals and enough observations to reduce noise.

The first implementation should calculate interval mean, standard deviation, and coefficient of variation. It must account for missing observations and timestamp precision.

## Alert quality

Every alert must identify the rule, severity, observed values, threshold, observation window, confidence rationale, and supporting evidence. Heuristic findings are investigative leads, not proof of compromise.
