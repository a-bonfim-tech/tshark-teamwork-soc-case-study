# Executive Summary

## Objective

Summarize this guided TryHackMe network-analysis case study for recruiters,
mentors, and security reviewers while preserving the boundary between reported
training findings and independently retained evidence.

## Context

This repository documents an authorized TryHackMe training scenario using
TShark command-line analysis. It records the exercise methodology and reported
findings related to phishing analysis, IOC handling, HTTP traffic review, and
threat-intelligence correlation.

The case is a learning and portfolio artifact. The repository does not retain
the supplied PCAP, command transcript, raw packet/output evidence, or dated
threat-intelligence lookup required to independently verify the reported
findings. It is not evidence from a real customer, employer, or third-party
production incident.

## Investigation Summary

| Area | Summary |
| --- | --- |
| Scenario | TryHackMe-guided analysis of a supplied phishing-related PCAP |
| Primary tool | TShark |
| Supporting source | VirusTotal, as reported in the training narrative |
| Reported finding | Look-alike phishing domain and HTTP POST activity |
| Retained evidence | Narrative documentation only; no PCAP, command output, packet excerpts, or dated threat-intelligence lookup |
| Outcome | Training-derived findings recorded; independent verification is not possible from retained repository evidence |

## Reported Training Findings

1. The training narrative reported a look-alike domain in HTTP traffic.
2. It reported PayPal impersonation.
3. It reported HTTP POST activity interpreted as credential-submission behavior.
4. It reported IOC normalization/defanging and VirusTotal correlation.
5. These statements are training-derived; the underlying packet and command evidence is not retained in this repository.

## Operational Value

This project documents:

- A guided network-analysis methodology using command-line tooling.
- An IOC-handling and safe-publication workflow.
- Phishing-investigation reasoning within a controlled training scenario.
- Defensive documentation in English, Portuguese, and German.
- Awareness of scope, authorization, evidence boundaries, and safe handling expectations.

## Risk Interpretation

If the reported training pattern were observed in a real organization, it would justify:

- User credential-compromise triage.
- Domain and URL blocking.
- Proxy, DNS, and endpoint log review.
- User notification and password reset workflow.
- Detection-rule development for similar look-alike domains.

These response actions are contextual recommendations only. They are not
evidence that a real organization was affected, that credentials were
compromised, or that any containment action was performed.

## Evidence Handling

No PCAP, command transcript, raw packet/output evidence, or dated
threat-intelligence lookup is retained in this repository. Published narrative
details should therefore be treated as training-derived rather than
independently verified findings.

The repository should not contain live credentials, session values, restricted
challenge-answer material, private packet captures, or sensitive third-party
data.

Security scope and reporting expectations are documented in
[SECURITY.md](SECURITY.md).

## Reviewer Notes

Recommended reading order:

1. `EXECUTIVE_SUMMARY.md`
2. `README.md`
3. `SECURITY.md`

The repository does not currently contain retained packet or command-output
evidence for independent reproduction.
