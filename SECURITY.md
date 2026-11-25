# Security Policy

## Project status

PacketHawk is an early-stage, offline-first network capture analysis tool. No stable release has been published. Security fixes are applied to the latest `main` branch.

## Reporting a vulnerability

Please do not publish exploitable details in a public issue or pull request.

Use GitHub's **Report a vulnerability** flow in the repository's Security tab to submit a private vulnerability report. Include:
- Affected commit or version.
- A concise impact description and prerequisites.
- A minimal reproduction or sanitized capture/configuration where possible.
- Any suggested mitigation.

Do not include credentials, personal data, or production packet captures containing sensitive information.

## Security scope

The primary security boundary is untrusted offline input:
- PCAP and PCAPNG block/packet parsing.
- Capture timestamp and length handling.
- TOML configuration parsing and validation.
- Bounded flow and detection state under adversarial traffic.
- JSON and terminal reporting of untrusted metadata.

PacketHawk does not perform live capture, active scanning, packet injection, blocking, or autonomous response.

## Known limitations

- Unsupported link types and selected fragment/extension-header cases are skipped or rejected.
- DNS parsing currently covers UDP DNS query names only; encrypted DNS and DNS-over-TCP are outside current coverage.
- Streaming detection expects nondecreasing timestamps. Late packets are ignored and counted.
- Bounded detector-state eviction can reduce detection coverage; eviction counters are included in reports.
- Detection findings are heuristic indicators, not proof of compromise.

Please include these limitations when assessing impact and avoid treating a heuristic alert as a confirmed security incident.
