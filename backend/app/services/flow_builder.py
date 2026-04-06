from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any
from uuid import uuid4

from app.detectors.heuristics import FlowFeature
from app.parsers.base import PacketRecord


def build_flows(packets: list[PacketRecord]) -> list[FlowFeature]:
    grouped: dict[tuple[str, str, int | None, str, int | None], list[PacketRecord]] = defaultdict(list)
    for packet in packets:
        key = (packet.protocol, packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)
        grouped[key].append(packet)

    flows: list[FlowFeature] = []
    for (protocol, src_ip, src_port, dst_ip, dst_port), entries in grouped.items():
        entries.sort(key=lambda item: item.timestamp)
        first_seen = entries[0].timestamp
        last_seen = entries[-1].timestamp
        metadata: dict[str, Any] = {
            "packet_timestamps": [entry.timestamp.timestamp() for entry in entries],
        }

        if protocol == "DNS":
            metadata["query_names"] = [entry.dns.get("query_name", "") for entry in entries if entry.dns]
            metadata["query_types"] = [int(entry.dns.get("query_type", 0)) for entry in entries if entry.dns]
        elif protocol == "HTTP":
            previews = [entry.http.get("preview") for entry in entries if entry.http.get("preview")]
            metadata["http_previews"] = previews[:5]
        elif protocol == "TLS":
            tls_records = [entry.tls for entry in entries if entry.tls]
            metadata["looks_like_tls"] = any(record.get("looks_like_tls") for record in tls_records)
            metadata["sni"] = next((record.get("sni") for record in tls_records if record.get("sni")), None)

        flows.append(
            FlowFeature(
                id=str(uuid4()),
                protocol=protocol,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                first_seen=_iso_or_none(first_seen),
                last_seen=_iso_or_none(last_seen),
                duration_seconds=max((last_seen - first_seen).total_seconds(), 0.0),
                packet_count=len(entries),
                byte_count=sum(entry.length for entry in entries),
                directionality=_directionality(src_ip, dst_ip),
                metadata=metadata,
            )
        )
    return flows


def _directionality(src_ip: str, dst_ip: str) -> str:
    if _is_private(src_ip) and not _is_private(dst_ip):
        return "outbound"
    if not _is_private(src_ip) and _is_private(dst_ip):
        return "inbound"
    return "lateral"


def _is_private(ip: str) -> bool:
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")


def _iso_or_none(value: datetime | None) -> str | None:
    return value.isoformat() if value else None
