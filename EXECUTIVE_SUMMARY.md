# Executive Summary

## Objective

Summarize the SOC-style network forensics case study in a form suitable for
recruiters, mentors, and security reviewers who need the business and
operational meaning before reading the technical investigation.

## Context

This repository documents an authorized TryHackMe training scenario using
TShark command-line analysis. The investigation focuses on phishing detection,
IOC extraction, HTTP traffic review, and threat-intelligence correlation.

The case is a learning and portfolio artifact. It is not evidence from a real
customer, employer, or third-party production incident.

## Investigation Summary

| Area | Summary |
| --- | --- |
| Scenario | Network traffic analysis of a phishing-related PCAP |
| Primary tool | TShark |
| Supporting source | VirusTotal correlation |
| Main finding | Look-alike phishing domain impersonating PayPal |
| Evidence type | HTTP traffic, POST activity, defanged IOC table, completion proof |
| Outcome | Phishing activity confirmed in the training scenario |

## Key Findings

1. A look-alike domain was identified in HTTP traffic.
2. The domain was associated with PayPal impersonation.
3. HTTP POST activity indicated credential-submission behavior in the scenario.
4. IOCs were normalized and defanged before publication.
5. The case follows a realistic Tier 1 / Tier 2 SOC reasoning flow.

## Operational Value

This project demonstrates:

- Network evidence review using command-line tooling.
- IOC extraction and safe publication practices.
- Phishing investigation reasoning.
- Defensive documentation in English, Portuguese, and German.
- Awareness of scope, authorization, and safe handling expectations.

## Risk Interpretation

If this were a real organization, the observed pattern would justify:

- User credential-compromise triage.
- Domain and URL blocking.
- Proxy, DNS, and endpoint log review.
- User notification and password reset workflow.
- Detection-rule development for similar look-alike domains.

These response actions are contextual recommendations only. They are not
evidence that a real organization was affected.

## Evidence Handling

Published indicators are defanged where appropriate. The repository should not
contain live credentials, session values, private packet captures, or sensitive
third-party data.

Security scope and reporting expectations are documented in
[SECURITY.md](SECURITY.md).

## Reviewer Notes

Recommended reading order:

1. `EXECUTIVE_SUMMARY.md`
2. `README.md`
3. Screenshot proof of completion
4. IOC table and methodology sections
