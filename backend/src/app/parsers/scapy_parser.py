from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import struct
from typing import Any

from app.parsers.base import PacketParser, PacketRecord

try:
    from scapy.all import DNS, DNSQR, IP, IPv6, Raw, TCP, UDP, rdpcap
except ImportError:  # pragma: no cover - exercised in environments without deps
    DNS = DNSQR = IP = IPv6 = Raw = TCP = UDP = None
    rdpcap = None


class ScapyPacketParser(PacketParser):
    def parse(self, file_path: str) -> list[PacketRecord]:
        if rdpcap is None:
            raise RuntimeError("Scapy is not installed")

        records: list[PacketRecord] = []
        packets = rdpcap(file_path)
        for packet in packets:
            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            if ip_layer is None:
                continue

            transport = "OTHER"
            src_port = dst_port = None
            protocol = "OTHER"
            tcp_flags = None
            dns_data: dict[str, str | int | float] = {}
            http_data: dict[str, str | int | float] = {}
            tls_data: dict[str, str | int | float] = {}

            if packet.haslayer(TCP):
                transport = "TCP"
                tcp_layer = packet[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                tcp_flags = str(tcp_layer.flags)
            elif packet.haslayer(UDP):
                transport = "UDP"
                udp_layer = packet[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)

            if packet.haslayer(DNS):
                protocol = "DNS"
                dns_layer = packet[DNS]
                query_name = ""
                query_type = 0
                if dns_layer.qd and isinstance(dns_layer.qd, DNSQR):
                    query_name = (dns_layer.qd.qname or b"").decode("utf-8", errors="ignore").rstrip(".")
                    query_type = int(dns_layer.qd.qtype or 0)
                dns_data = {
                    "query_name": query_name,
                    "query_type": query_type,
                    "query_length": len(query_name),
                    "answer_count": int(dns_layer.ancount or 0),
                }
            elif src_port in {80, 8080} or dst_port in {80, 8080}:
                protocol = "HTTP"
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw].load[:512])
                    text = payload.decode("latin-1", errors="ignore")
                    first_line = text.splitlines()[0] if text.splitlines() else ""
                    http_data = {"preview": first_line[:200]}
            elif src_port in {443, 8443} or dst_port in {443, 8443}:
                protocol = "TLS"
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw].load[:512])
                    tls_data = _parse_tls_payload(payload)

            records.append(
                PacketRecord(
                    timestamp=datetime.fromtimestamp(float(packet.time), tz=timezone.utc),
                    src_ip=str(ip_layer.src),
                    dst_ip=str(ip_layer.dst),
                    src_port=src_port,
                    dst_port=dst_port,
                    transport=transport,
                    protocol=protocol,
                    length=len(packet),
                    tcp_flags=tcp_flags,
                    dns=dns_data,
                    http=http_data,
                    tls=tls_data,
                )
            )
        return records


def _parse_tls_payload(payload: bytes) -> dict[str, Any]:
    tls_data: dict[str, Any] = {
        "record_hint": payload[:3].hex(),
        "looks_like_tls": len(payload) >= 3 and payload[0] in {20, 21, 22, 23} and payload[1] == 3,
    }
    if len(payload) < 5 or payload[0] != 22:
        return tls_data

    tls_data["record_version"] = _version_string(payload[1:3])

    try:
        record_length = struct.unpack("!H", payload[3:5])[0]
        body_end = min(len(payload), 5 + record_length)
        if body_end - 5 < 4:
            return tls_data

        handshake_type = payload[5]
        tls_data["handshake_type"] = _handshake_name(handshake_type)
        handshake_length = int.from_bytes(payload[6:9], "big")
        handshake_body = payload[9 : min(body_end, 9 + handshake_length)]

        if handshake_type == 1:
            tls_data.update(_parse_client_hello(handshake_body))
        elif handshake_type == 2:
            tls_data.update(_parse_server_hello(handshake_body))
    except Exception:
        return tls_data

    return tls_data


def _parse_client_hello(body: bytes) -> dict[str, Any]:
    if len(body) < 34:
        return {}

    cursor = 0
    client_version = _version_string(body[cursor : cursor + 2])
    cursor += 2
    cursor += 32

    if cursor >= len(body):
        return {"client_version": client_version}

    session_id_length = body[cursor]
    cursor += 1
    if cursor + session_id_length > len(body):
        return {"client_version": client_version, "session_id_length": session_id_length}
    cursor += session_id_length

    if cursor + 2 > len(body):
        return {"client_version": client_version, "session_id_length": session_id_length}
    cipher_suite_bytes = struct.unpack("!H", body[cursor : cursor + 2])[0]
    cursor += 2
    cipher_suites: list[int] = []
    cipher_end = min(len(body), cursor + cipher_suite_bytes)
    while cursor + 2 <= cipher_end:
        cipher_suites.append(struct.unpack("!H", body[cursor : cursor + 2])[0])
        cursor += 2

    if cursor >= len(body):
        return _client_hello_result(client_version, session_id_length, cipher_suites, [], None, [])

    compression_length = body[cursor]
    cursor += 1 + compression_length
    if cursor > len(body):
        return _client_hello_result(client_version, session_id_length, cipher_suites, [], None, [])

    extension_types: list[int] = []
    alpn_protocols: list[str] = []
    sni: str | None = None
    supported_groups: list[int] = []

    if cursor + 2 <= len(body):
        extensions_length = struct.unpack("!H", body[cursor : cursor + 2])[0]
        cursor += 2
        extension_end = min(len(body), cursor + extensions_length)
        while cursor + 4 <= extension_end:
            ext_type = struct.unpack("!H", body[cursor : cursor + 2])[0]
            ext_length = struct.unpack("!H", body[cursor + 2 : cursor + 4])[0]
            cursor += 4
            ext_value = body[cursor : min(extension_end, cursor + ext_length)]
            cursor += ext_length
            extension_types.append(ext_type)

            if ext_type == 0:
                sni = _parse_sni_extension(ext_value) or sni
            elif ext_type == 16:
                alpn_protocols = _parse_alpn_extension(ext_value) or alpn_protocols
            elif ext_type == 10:
                supported_groups = _parse_supported_groups_extension(ext_value) or supported_groups

    return _client_hello_result(client_version, session_id_length, cipher_suites, extension_types, sni, alpn_protocols, supported_groups)


def _parse_server_hello(body: bytes) -> dict[str, Any]:
    if len(body) < 38:
        return {}

    cursor = 0
    server_version = _version_string(body[cursor : cursor + 2])
    cursor += 2
    cursor += 32
    if cursor >= len(body):
        return {"client_version": server_version}

    session_id_length = body[cursor]
    cursor += 1 + session_id_length
    if cursor + 3 > len(body):
        return {
            "client_version": server_version,
            "session_id_length": session_id_length,
        }

    selected_cipher = struct.unpack("!H", body[cursor : cursor + 2])[0]
    cursor += 2
    cursor += 1

    extension_types: list[int] = []
    alpn_protocols: list[str] = []
    if cursor + 2 <= len(body):
        extensions_length = struct.unpack("!H", body[cursor : cursor + 2])[0]
        cursor += 2
        extension_end = min(len(body), cursor + extensions_length)
        while cursor + 4 <= extension_end:
            ext_type = struct.unpack("!H", body[cursor : cursor + 2])[0]
            ext_length = struct.unpack("!H", body[cursor + 2 : cursor + 4])[0]
            cursor += 4
            ext_value = body[cursor : min(extension_end, cursor + ext_length)]
            cursor += ext_length
            extension_types.append(ext_type)
            if ext_type == 16:
                parsed = _parse_server_alpn_extension(ext_value)
                if parsed:
                    alpn_protocols = [parsed]

    ja3_source = f"{server_version},{selected_cipher},{'-'.join(str(item) for item in extension_types)}"
    return {
        "client_version": server_version,
        "session_id_length": session_id_length,
        "cipher_suites_sample": [f"0x{selected_cipher:04x}"],
        "alpn_protocols": alpn_protocols,
        "ja3_like_fingerprint": hashlib.md5(ja3_source.encode("utf-8")).hexdigest(),
    }


def _client_hello_result(
    client_version: str,
    session_id_length: int,
    cipher_suites: list[int],
    extension_types: list[int],
    sni: str | None,
    alpn_protocols: list[str],
    supported_groups: list[int] | None = None,
) -> dict[str, Any]:
    ja3_parts = [
        client_version,
        "-".join(str(item) for item in cipher_suites),
        "-".join(str(item) for item in extension_types),
        "-".join(str(item) for item in (supported_groups or [])),
        "-".join(alpn_protocols),
    ]
    return {
        "client_version": client_version,
        "session_id_length": session_id_length,
        "sni": sni,
        "alpn_protocols": alpn_protocols,
        "cipher_suites_sample": [f"0x{item:04x}" for item in cipher_suites[:5]],
        "ja3_like_fingerprint": hashlib.md5(",".join(ja3_parts).encode("utf-8")).hexdigest(),
    }


def _parse_sni_extension(value: bytes) -> str | None:
    if len(value) < 5:
        return None
    cursor = 2
    while cursor + 3 <= len(value):
        name_type = value[cursor]
        name_length = struct.unpack("!H", value[cursor + 1 : cursor + 3])[0]
        cursor += 3
        if cursor + name_length > len(value):
            return None
        if name_type == 0:
            return value[cursor : cursor + name_length].decode("utf-8", errors="ignore")
        cursor += name_length
    return None


def _parse_alpn_extension(value: bytes) -> list[str]:
    if len(value) < 2:
        return []
    cursor = 2
    protocols: list[str] = []
    while cursor < len(value):
        if cursor >= len(value):
            break
        item_length = value[cursor]
        cursor += 1
        if cursor + item_length > len(value):
            break
        protocols.append(value[cursor : cursor + item_length].decode("ascii", errors="ignore"))
        cursor += item_length
    return protocols


def _parse_server_alpn_extension(value: bytes) -> str | None:
    if not value:
        return None
    item_length = value[0]
    if 1 + item_length > len(value):
        return None
    return value[1 : 1 + item_length].decode("ascii", errors="ignore")


def _parse_supported_groups_extension(value: bytes) -> list[int]:
    if len(value) < 2:
        return []
    cursor = 2
    groups: list[int] = []
    while cursor + 2 <= len(value):
        groups.append(struct.unpack("!H", value[cursor : cursor + 2])[0])
        cursor += 2
    return groups


def _version_string(value: bytes) -> str:
    if len(value) < 2:
        return "unknown"
    return f"{value[0]}.{value[1]}"


def _handshake_name(value: int) -> str:
    return {
        1: "client_hello",
        2: "server_hello",
        11: "certificate",
        12: "server_key_exchange",
        14: "server_hello_done",
        16: "client_key_exchange",
    }.get(value, f"handshake_{value}")
