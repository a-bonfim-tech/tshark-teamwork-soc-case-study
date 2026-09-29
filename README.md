# TShark SOC Network Analysis Case Study

A reproducible network-analysis portfolio project demonstrating hands-on **TShark CLI**, packet inspection, TCP conversation analysis, HTTP filtering, request/response correlation, timeline reconstruction and evidence handling.

The repository contains two explicitly separate evidence classes:

1. **Independent reproducible evidence** — a synthetic PCAP, generator, retained TShark outputs, hashes and reproduction instructions that can be independently verified.
2. **Historical guided training** — documentation of an earlier TryHackMe exercise whose original PCAP and command evidence are not retained.

The independent lab demonstrates current technical execution and remains separate from the historical TryHackMe exercise.

## What this project demonstrates

- Packet-level inspection with TShark
- Source/destination and port identification
- TCP conversation analysis
- HTTP request extraction
- HTTP method, Host and URI inspection
- Controlled HTTP POST inspection
- Request/response correlation
- Timeline reconstruction
- Reproducible synthetic PCAP generation
- SHA-256 evidence integrity checks
- Separation of direct observation from interpretation

## Evidence at a glance

The independent controlled lab retains a deterministic 10-packet IPv4/TCP/HTTP conversation.

| Observable | Retained result |
| --- | --- |
| Client | `192.0.2.10:51515` |
| Server | `192.0.2.20:80` |
| HTTP Host | `soc-lab.example` |
| Request 1 | `GET /status` |
| Response 1 | `200` |
| Request 2 | `POST /submit` |
| Response 2 | `204` |
| Synthetic form values | `training-user` / `training-only-not-a-secret` |
| Packet count | `10` |
| PCAP SHA-256 | `11637224b11102618aecfe98cac80a30834b4460129d9e54aed68f70076d67bc` |

Direct evidence:

- [PCAP](evidence/capture.pcap)
- [Packet inventory](evidence/packet-summary.txt)
- [TCP conversations](evidence/tcp-conversations.txt)
- [HTTP requests](evidence/http-requests.txt)
- [HTTP POST dissection](evidence/http-posts.txt)
- [HTTP timeline](evidence/timeline.txt)
- [Tool versions](evidence/tool-versions.txt)
- [SHA-256 manifest](evidence/sha256.txt)
- [Evidence notes](evidence/README.md)

## Technical workflow

~~~text
Python standard-library generator
        |
        v
deterministic synthetic PCAP
        |
        v
TShark packet inspection
        |
        +--> packet inventory
        +--> TCP conversation statistics
        +--> HTTP request filtering
        +--> POST field inspection
        +--> request/response timeline
        |
        v
retained outputs + SHA-256 verification
~~~

The lab is fully self-contained and uses synthetic traffic, test values and retained local evidence.

## Observed results

TShark directly shows:

- exactly 10 packets;
- one TCP conversation between `192.0.2.10:51515` and `192.0.2.20:80`;
- `GET /status`;
- `POST /submit`;
- `Host: soc-lab.example`;
- HTTP responses `200` and `204`;
- the synthetic POST fields `username=training-user` and `password=training-only-not-a-secret`;
- the GET preceding the POST in the retained HTTP timeline.

The generator produced the same PCAP SHA-256 hash on consecutive executions during validation.

## SOC relevance

The lab exercises mechanics directly relevant to Tier 1 network-focused triage:

- reading packet evidence;
- identifying communicating endpoints;
- recognizing protocol behavior;
- filtering for relevant traffic;
- correlating requests and responses;
- reconstructing event order;
- extracting observable HTTP attributes;
- preserving analysis artifacts;
- distinguishing observation from inference.


## Reproduce

Requirements:

- Python 3
- TShark

Generate the deterministic PCAP:

~~~sh
python3 lab/generate_synthetic_pcap.py --output evidence/capture.pcap
~~~

Inspect the packet inventory:

~~~sh
tshark -r evidence/capture.pcap -n \
  -T fields \
  -E header=y \
  -E separator=/t \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e tcp.srcport \
  -e ip.dst \
  -e tcp.dstport \
  -e tcp.len \
  -e _ws.col.Protocol
~~~

Inspect TCP conversations:

~~~sh
tshark -r evidence/capture.pcap -n -q -z conv,tcp
~~~

Extract HTTP requests:

~~~sh
tshark -r evidence/capture.pcap -n \
  -Y 'http.request' \
  -T fields \
  -E header=y \
  -E separator=/t \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e http.request.method \
  -e http.host \
  -e http.request.uri
~~~

Full reproduction instructions: [REPRODUCE.md](REPRODUCE.md).

## Evidence boundary

### Independent reproducible evidence

The files under `lab/` and `evidence/` were created for this repository as a controlled synthetic lab.

They directly demonstrate current TShark/network-analysis execution with retained input, commands, output and integrity hashes.

### Historical guided training

This repository also documents an earlier authorized TryHackMe exercise, **TShark Challenge I – Teamwork**.

Official room:

https://tryhackme.com/room/tsharkchallengesone

The historical exercise involved analysis of a supplied training PCAP and a phishing-related scenario. The original TryHackMe PCAP, original TShark command transcript, raw packet excerpts, completion screenshot and dated threat-intelligence lookup are **not retained in this repository**.

Earlier repository narratives reported a look-alike domain, HTTP POST activity interpreted as credential submission and threat-intelligence correlation. Those statements remain historical training context and are separate from the independently reproducible evidence set.

No challenge answers, protected TryHackMe PCAP or reconstructed historical evidence are published here.

### Independent lab scope

The synthetic lab uses controlled traffic and test values to demonstrate reproducible TShark analysis mechanics. Historical TryHackMe findings and real-world incident provenance remain outside this evidence set.

## Repository structure

~~~text
.
├── README.md
├── EXECUTIVE_SUMMARY.md
├── REPRODUCE.md
├── SECURITY.md
├── lab/
│   └── generate_synthetic_pcap.py
└── evidence/
    ├── README.md
    ├── capture.pcap
    ├── packet-summary.txt
    ├── tcp-conversations.txt
    ├── http-requests.txt
    ├── http-posts.txt
    ├── timeline.txt
    ├── tool-versions.txt
    └── sha256.txt
~~~

## Evidence integrity

Verify the retained manifest:

~~~sh
shasum -a 256 -c evidence/sha256.txt
~~~

The manifest covers the generator, reproduction guide, PCAP and retained analysis outputs.

Security scope and publication boundaries are documented in [SECURITY.md](SECURITY.md).
