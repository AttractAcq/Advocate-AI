"""Authoritative, no-forwarding UDP DNS simulator on unprivileged loopback."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import socketserver
import struct

ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY = json.loads((ROOT / "infrastructure/lab/topology.json").read_text())
NAMES = TOPOLOGY["dns"]["names"]


def decode_question(packet: bytes) -> tuple[str, int] | None:
    if len(packet) < 17 or struct.unpack("!H", packet[4:6])[0] != 1:
        return None
    labels: list[str] = []
    offset = 12
    while offset < len(packet):
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        if size > 63 or offset + size > len(packet):
            return None
        try:
            labels.append(packet[offset:offset + size].decode("ascii").lower())
        except UnicodeDecodeError:
            return None
        offset += size
    else:
        return None
    if offset + 4 > len(packet):
        return None
    return ".".join(labels), offset + 4


def reply(packet: bytes) -> bytes:
    parsed = decode_question(packet)
    if parsed is None:
        return b""
    name, end = parsed
    question = packet[12:end]
    qtype, qclass = struct.unpack("!HH", packet[end - 4:end])
    address = NAMES.get(name) if qtype == 1 and qclass == 1 else None
    flags = 0x8180 if address else 0x8183
    header = packet[:2] + struct.pack("!HHHHH", flags, 1, int(bool(address)), 0, 0)
    if not address:
        return header + question
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    return header + question + answer


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        request, connection = self.request
        response = reply(request)
        if response:
            connection.sendto(response, self.client_address)


def query(name: str, timeout: float = 1) -> str | None:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii")
                      for label in name.lower().split(".")) + b"\x00"
    packet = struct.pack("!HHHHHH", 0x5341, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(packet, (TOPOLOGY["bind"], TOPOLOGY["dns"]["port"]))
        response, _ = client.recvfrom(512)
    if len(response) < 12 or response[:2] != packet[:2]:
        raise ValueError("invalid synthetic DNS response")
    if struct.unpack("!H", response[6:8])[0] == 0:
        return None
    return socket.inet_ntoa(response[-4:])


def main() -> None:
    with socketserver.UDPServer((TOPOLOGY["bind"], TOPOLOGY["dns"]["port"]), Handler) as server:
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
