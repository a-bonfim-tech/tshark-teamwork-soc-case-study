# Reproduce the Independent TShark Lab

This procedure reproduces the synthetic lab evidence. It does not reproduce the historical TryHackMe capture.

## Requirements

- Python 3
- TShark

No Python third-party packages, Internet access, packet capture or elevated privileges are required.

## Generate the deterministic PCAP

    python3 lab/generate_synthetic_pcap.py --output evidence/capture.pcap

## Inspect packet inventory

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

## Inspect TCP conversations

    tshark -r evidence/capture.pcap -n -q -z conv,tcp

## Extract HTTP requests

    tshark -r evidence/capture.pcap -n \
      -Y 'http.request' \
      -T fields \
      -E header=y \
      -E separator=/t \
      -e frame.number \
      -e frame.time_relative \
      -e ip.src \
      -e ip.dst \
      -e http.request.method \
      -e http.host \
      -e http.request.uri

## Inspect the synthetic POST

    tshark -r evidence/capture.pcap -n \
      -Y 'http.request.method == "POST"' \
      -V

## Reconstruct the HTTP timeline

    tshark -r evidence/capture.pcap -n \
      -Y 'http' \
      -T fields \
      -E header=y \
      -E separator=/t \
      -e frame.number \
      -e frame.time_relative \
      -e ip.src \
      -e ip.dst \
      -e http.request.method \
      -e http.request.uri \
      -e http.response.code

## Expected boundaries

Expected endpoints are only:

    192.0.2.10
    192.0.2.20

Expected HTTP Host:

    soc-lab.example

The POST data is intentionally synthetic:

    username=training-user
    password=training-only-not-a-secret

This lab does not validate or reconstruct the historical TryHackMe PCAP.
