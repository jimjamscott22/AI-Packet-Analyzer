from datetime import datetime, timedelta, timezone

from app.parsers.base import PacketRecord
from app.services.flow_builder import build_flows


def test_build_flows_groups_packets_by_protocol_and_tuple():
    base_time = datetime.now(tz=timezone.utc)
    packets = [
        PacketRecord(
            timestamp=base_time,
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=50000,
            dst_port=53,
            transport="UDP",
            protocol="DNS",
            length=80,
            dns={"query_name": "a.example.com", "query_type": 1},
        ),
        PacketRecord(
            timestamp=base_time + timedelta(seconds=1),
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=50000,
            dst_port=53,
            transport="UDP",
            protocol="DNS",
            length=82,
            dns={"query_name": "b.example.com", "query_type": 1},
        ),
    ]

    flows = build_flows(packets)

    assert len(flows) == 1
    assert flows[0].packet_count == 2
    assert flows[0].metadata["query_names"] == ["a.example.com", "b.example.com"]
