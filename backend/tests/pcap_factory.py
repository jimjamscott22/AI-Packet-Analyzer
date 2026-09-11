from __future__ import annotations

from pathlib import Path

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, wrpcap


def write_dns_tunnel_pcap(path: Path) -> Path:
    packets = []
    for index in range(20):
        query_name = f"x{index}q9v2b8c7d6e5f4g3h2.tunnel.example."
        packet = (
            IP(src="192.168.1.20", dst="1.1.1.1")
            / UDP(sport=51000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=query_name, qtype=16))
        )
        packet.time = float(index)
        packets.append(packet)
    wrpcap(str(path), packets)
    return path


def write_benign_dns_pcap(path: Path) -> Path:
    names = ["www.example.com.", "api.example.com.", "cdn.example.com."]
    packets = []
    for index, name in enumerate(names):
        packet = (
            IP(src="192.168.1.21", dst="8.8.8.8")
            / UDP(sport=51100 + index, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=name, qtype=1))
        )
        packet.time = float(index * 3)
        packets.append(packet)
    wrpcap(str(path), packets)
    return path


def write_beaconing_tls_pcap(path: Path) -> Path:
    packets = []
    payload = bytes([0x17, 0x03, 0x03, 0x00, 0x20]) + bytes(range(32))
    for index in range(5):
        packet = (
            IP(src="192.168.1.15", dst="198.51.100.22")
            / TCP(sport=52000, dport=443, flags="PA", seq=index * 40, ack=1)
            / Raw(load=payload)
        )
        packet.time = float(index * 10)
        packets.append(packet)
    wrpcap(str(path), packets)
    return path


def write_suspicious_tls_pcap(path: Path) -> Path:
    packets = []
    payloads = [
        bytes([0x17, 0x03, 0x03, 0x00, 0x10]) + bytes(range(16)),
        bytes([0x17, 0x03, 0x01, 0x00, 0x12]) + bytes(range(18)),
        bytes([0x17, 0x03, 0x03, 0x00, 0x14]) + bytes(range(20)),
        bytes([0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x00]),
    ]
    for index, payload in enumerate(payloads):
        packet = (
            IP(src="192.168.1.30", dst="198.51.100.23")
            / TCP(sport=53000, dport=443, flags="PA", seq=index * 50, ack=1)
            / Raw(load=payload)
        )
        packet.time = float(index * 2)
        packets.append(packet)
    wrpcap(str(path), packets)
    return path


def write_benign_tls_pcap(path: Path) -> Path:
    hello = _client_hello_payload(sni="cdn.example", alpn_protocols=["h2"])
    timestamps = [0.0, 3.0, 11.0, 18.0, 30.0, 47.0, 60.0, 82.0]
    packets = []
    for index, timestamp in enumerate(timestamps):
        payload = hello if index == 0 else bytes([0x17, 0x03, 0x03, 0x00, 0x80]) + bytes(range(128))
        packet = (
            IP(src="192.168.1.31", dst="198.51.100.24")
            / TCP(sport=53001, dport=443, flags="PA", seq=index * 200, ack=1)
            / Raw(load=payload)
        )
        packet.time = timestamp
        packets.append(packet)
    wrpcap(str(path), packets)
    return path


def write_sample_captures(directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    return [
        write_benign_dns_pcap(directory / "benign-dns.pcap"),
        write_benign_tls_pcap(directory / "benign-tls.pcap"),
        write_dns_tunnel_pcap(directory / "suspicious-dns-tunnel.pcap"),
        write_beaconing_tls_pcap(directory / "suspicious-tls-beacon.pcap"),
        write_suspicious_tls_pcap(directory / "suspicious-tls-opaque.pcap"),
    ]


def _client_hello_payload(*, sni: str | None, alpn_protocols: list[str]) -> bytes:
    cipher_suites = b"\x13\x01\x13\x02"
    body = bytearray()
    body.extend(b"\x03\x03")
    body.extend(bytes(range(32)))
    body.append(0)
    body.extend(len(cipher_suites).to_bytes(2, "big"))
    body.extend(cipher_suites)
    body.extend(b"\x01\x00")

    extensions = bytearray()
    if sni:
        host = sni.encode("ascii")
        server_name = b"\x00" + len(host).to_bytes(2, "big") + host
        server_name_list = len(server_name).to_bytes(2, "big") + server_name
        extensions.extend((0).to_bytes(2, "big"))
        extensions.extend(len(server_name_list).to_bytes(2, "big"))
        extensions.extend(server_name_list)

    if alpn_protocols:
        encoded = bytearray()
        for protocol in alpn_protocols:
            data = protocol.encode("ascii")
            encoded.append(len(data))
            encoded.extend(data)
        alpn_body = len(encoded).to_bytes(2, "big") + encoded
        extensions.extend((16).to_bytes(2, "big"))
        extensions.extend(len(alpn_body).to_bytes(2, "big"))
        extensions.extend(alpn_body)

    supported_groups = b"\x00\x04\x00\x1d\x00\x17"
    extensions.extend((10).to_bytes(2, "big"))
    extensions.extend(len(supported_groups).to_bytes(2, "big"))
    extensions.extend(supported_groups)

    body.extend(len(extensions).to_bytes(2, "big"))
    body.extend(extensions)

    handshake = bytearray()
    handshake.append(1)
    handshake.extend(len(body).to_bytes(3, "big"))
    handshake.extend(body)

    record = bytearray()
    record.extend(b"\x16\x03\x01")
    record.extend(len(handshake).to_bytes(2, "big"))
    record.extend(handshake)
    return bytes(record)


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[2]
    written = write_sample_captures(repo_root / "samples")
    for path in written:
        print(path)
