from __future__ import annotations

from datetime import datetime, timezone

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
                    tls_data = {
                        "record_hint": payload[:3].hex(),
                        "looks_like_tls": payload.startswith(b"\x16\x03"),
                    }

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
