# Security Policy

## Scope

This repository contains two defensive-learning components:

1. historical documentation of an authorized TryHackMe training exercise; and
2. an independent synthetic TShark lab created specifically for reproducible portfolio evidence.

The independent lab uses documentation-range IP addresses, fictitious HTTP data and a locally generated PCAP. It does not require live traffic, third-party systems or real credentials.

## Repository Safety Boundary

The repository should not contain:

- active credentials;
- authentication tokens;
- cookies or session secrets;
- undeclared personal data;
- private packet captures from real third-party environments;
- live malicious links presented without appropriate handling;
- protected TryHackMe challenge artifacts or answers;
- instructions implying authorization to inspect systems owned by others.

The strings `training-user` and `training-only-not-a-secret` in the independent lab are intentionally synthetic test values.

## Historical Training Boundary

The historical TryHackMe PCAP and original command evidence are not retained here.

The independent synthetic evidence must not be represented as:

- the original TryHackMe capture;
- proof of historical TryHackMe packet findings;
- evidence of a real phishing incident;
- evidence of real credential compromise.

## Reporting a Concern

Open a GitHub issue if you identify:

- sensitive packet data;
- credentials, tokens or session values;
- unexpected personal information;
- misleading evidence provenance;
- unsafe URLs or IOCs;
- incorrect scope or authorization language.

Do not post sensitive values directly in public issue text. Identify the affected path and provide only the minimum description necessary.

## Triage Process

Reports are handled in this order:

1. preserve the report and affected file path;
2. determine whether the content is sensitive, unsafe or inaccurate;
3. redact, defang or remove material when required;
4. update the evidence narrative if the correction affects interpretation;
5. record the correction in Git history.

## Intended Use

This repository supports defensive SOC and network-analysis learning.

It is not authorization to inspect, capture, test or access networks, accounts or systems owned by others.
