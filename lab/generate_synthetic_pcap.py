#!/usr/bin/env python3

import argparse
import ipaddress
import struct
from pathlib import Path


CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_PORT = 51515
SERVER_PORT = 80

CLIENT_INITIAL_SEQ = 1000
SERVER_INITIAL_SEQ = 9000

BASE_TIMESTAMP = 1_700_000_000

SYN = 0x02
ACK = 0x10
PSH = 0x08
FIN = 0x01


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"

    total = sum(
        (data[index] << 8) + data[index + 1]
        for index in range(0, len(data), 2)
    )

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def ipv4_bytes(address: str) -> bytes:
    return ipaddress.IPv4Address(address).packed


def build_tcp_segment(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    offset_and_flags = (5 << 12) | flags
    window = 64240

    header_without_checksum = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        offset_and_flags,
        window,
        0,
        0,
    )

    pseudo_header = (
        ipv4_bytes(source_ip)
        + ipv4_bytes(destination_ip)
        + struct.pack("!BBH", 0, 6, len(header_without_checksum) + len(payload))
    )

    tcp_checksum = checksum(
        pseudo_header + header_without_checksum + payload
    )

    header = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        offset_and_flags,
        window,
        tcp_checksum,
        0,
    )

    return header + payload


def build_ipv4_packet(
    source_ip: str,
    destination_ip: str,
    identification: int,
    tcp_segment: bytes,
) -> bytes:
    version_ihl = 0x45
    total_length = 20 + len(tcp_segment)

    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        identification,
        0x4000,
        64,
        6,
        0,
        ipv4_bytes(source_ip),
        ipv4_bytes(destination_ip),
    )

    ip_checksum = checksum(header_without_checksum)

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        identification,
        0x4000,
        64,
        6,
        ip_checksum,
        ipv4_bytes(source_ip),
        ipv4_bytes(destination_ip),
    )

    return header + tcp_segment


def packet(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
    identification: int,
    payload: bytes = b"",
) -> bytes:
    segment = build_tcp_segment(
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        flags,
        payload,
    )

    return build_ipv4_packet(
        source_ip,
        destination_ip,
        identification,
        segment,
    )


def build_packets() -> list[bytes]:
    get_request = (
        b"GET /status HTTP/1.1\r\n"
        b"Host: soc-lab.example\r\n"
        b"User-Agent: synthetic-soc-lab/1.0\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
    )

    get_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 2\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
        b"OK"
    )

    post_body = (
        b"username=training-user"
        b"&password=training-only-not-a-secret"
    )

    post_request = (
        b"POST /submit HTTP/1.1\r\n"
        b"Host: soc-lab.example\r\n"
        b"User-Agent: synthetic-soc-lab/1.0\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(post_body)}\r\n".encode("ascii")
        + b"Connection: keep-alive\r\n"
        + b"\r\n"
        + post_body
    )

    post_response = (
        b"HTTP/1.1 204 No Content\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    client_seq = CLIENT_INITIAL_SEQ
    server_seq = SERVER_INITIAL_SEQ

    packets: list[bytes] = []

    packets.append(
        packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            SERVER_PORT,
            client_seq,
            0,
            SYN,
            0x1001,
        )
    )
    client_seq += 1

    packets.append(
        packet(
            SERVER_IP,
            CLIENT_IP,
            SERVER_PORT,
            CLIENT_PORT,
            server_seq,
            client_seq,
            SYN | ACK,
            0x1002,
        )
    )
    server_seq += 1

    packets.append(
        packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            SERVER_PORT,
            client_seq,
            server_seq,
            ACK,
            0x1003,
        )
    )

    packets.append(
        packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            SERVER_PORT,
            client_seq,
            server_seq,
            PSH | ACK,
            0x1004,
            get_request,
        )
    )
    client_seq += len(get_request)

    packets.append(
        packet(
            SERVER_IP,
            CLIENT_IP,
            SERVER_PORT,
            CLIENT_PORT,
            server_seq,
            client_seq,
            PSH | ACK,
            0x1005,
            get_response,
        )
    )
    server_seq += len(get_response)

    packets.append(
        packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            SERVER_PORT,
            client_seq,
            server_seq,
            PSH | ACK,
            0x1006,
            post_request,
        )
    )
    client_seq += len(post_request)

    packets.append(
        packet(
            SERVER_IP,
            CLIENT_IP,
            SERVER_PORT,
            CLIENT_PORT,
            server_seq,
            client_seq,
            PSH | ACK,
            0x1007,
            post_response,
        )
    )
    server_seq += len(post_response)

    packets.append(
        packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            SERVER_PORT,
            client_seq,
            server_seq,
            FIN | ACK,
            0x1008,
        )
    )
    client_seq += 1

    packets.append(
        packet(
            SERVER_IP,
            CLIENT_IP,
            SERVER_PORT,
            CLIENT_PORT,
            server_seq,
            client_seq,
            FIN | ACK,
            0x1009,
        )
    )
    server_seq += 1

    packets.append(
        packet(
            CLIENT_IP,
            SERVER_IP,
            CLIENT_PORT,
            SERVER_PORT,
            client_seq,
            server_seq,
            ACK,
            0x100A,
        )
    )

    return packets


def write_pcap(output: Path, packets: list[bytes]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    global_header = struct.pack(
        "<IHHIIII",
        0xA1B2C3D4,
        2,
        4,
        0,
        0,
        65535,
        101,
    )

    with output.open("wb") as handle:
        handle.write(global_header)

        for index, payload in enumerate(packets):
            timestamp_seconds = BASE_TIMESTAMP
            timestamp_microseconds = index * 100_000

            handle.write(
                struct.pack(
                    "<IIII",
                    timestamp_seconds,
                    timestamp_microseconds,
                    len(payload),
                    len(payload),
                )
            )
            handle.write(payload)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a deterministic synthetic IPv4/TCP/HTTP PCAP "
            "for the independent TShark evidence lab."
        )
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("evidence/capture.pcap"),
        help="Output PCAP path (default: evidence/capture.pcap)",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.output.suffix.lower() != ".pcap":
        raise SystemExit("Output path must use the .pcap extension.")

    packets = build_packets()

    if len(packets) != 10:
        raise SystemExit("Internal error: expected exactly 10 packets.")

    write_pcap(args.output, packets)

    print(f"Wrote {len(packets)} synthetic packets to {args.output}")


if __name__ == "__main__":
    main()
