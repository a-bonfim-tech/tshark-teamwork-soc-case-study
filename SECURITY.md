# Security Policy

## Scope

This repository documents a SOC-style network forensics investigation based on
an authorized TryHackMe training room. It is intended for defensive learning,
portfolio review, and audit-friendly investigation documentation.

The repository should not contain:

- Active credentials
- Undeclared personal data
- Raw sensitive packet captures from real third-party environments
- Live malicious links without defanging
- Instructions that imply authorization to investigate or test third-party
  systems

## Reporting a Concern

Open a GitHub issue if you identify:

- Sensitive packet data that should be removed or redacted
- Credentials, tokens, or session values
- IOCs that are not safely defanged
- Misleading attribution or threat-intelligence claims
- Incorrect scope or authorization language

Do not post sensitive values in public issue text. Provide the affected file
path and a general description.

## Triage Process

Reports are handled in this order:

1. Preserve the report and affected file path.
2. Confirm whether the content is sensitive, unsafe, or inaccurate.
3. Redact, defang, or remove the affected material.
4. Update the investigation narrative if the correction changes the conclusion.
5. Record the correction in commit history.

## Intended Use

This repository supports defensive SOC learning. It is not authorization to
inspect networks, accounts, packet captures, or systems owned by others.
