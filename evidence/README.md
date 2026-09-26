# Independent Controlled TShark Lab — Evidence

This directory contains evidence generated from a synthetic, independently constructed IPv4/TCP/HTTP PCAP.

It is not evidence from the historical TryHackMe exercise and does not retroactively validate any historical training finding.

## Execution record

- Execution recorded at UTC: 2026-09-26T17:34:02Z
- Packet timestamps: synthetic and fixed by the generator
- First packet timestamp: 2023-11-14T22:13:20.000000Z
- Final packet timestamp: 2023-11-14T22:13:20.900000Z
- Client: 192.0.2.10:51515
- Server: 192.0.2.20:80
- HTTP Host: soc-lab.example
- Packet count: 10

## Synthetic scenario

The generator constructs one deterministic TCP conversation containing:

1. TCP three-way handshake
2. GET /status
3. HTTP 200 response
4. POST /submit
5. HTTP 204 response
6. TCP connection close

The POST body contains the intentionally fictitious values:

- username: training-user
- password: training-only-not-a-secret

These are synthetic lab strings, not credentials.

## Retained artifacts

- capture.pcap — synthetic packet input
- packet-summary.txt — packet-level inventory
- tcp-conversations.txt — TShark TCP conversation statistics
- http-requests.txt — extracted HTTP requests
- http-posts.txt — verbose inspection of the synthetic POST
- timeline.txt — HTTP request/response timeline
- tool-versions.txt — execution timestamp and tool versions
- sha256.txt — SHA-256 hashes of retained project/evidence artifacts

## Evidence boundary

Directly demonstrated here:

- packet inventory
- source/destination identification
- TCP conversation analysis
- HTTP method, Host and URI inspection
- controlled HTTP POST inspection
- timeline reconstruction
- TShark CLI analysis
- deterministic PCAP generation
- artifact hashing

Not established here:

- real phishing
- real credential theft
- malicious-domain reputation
- production traffic
- historical TryHackMe packet findings

No traffic was transmitted to a network during PCAP generation.
