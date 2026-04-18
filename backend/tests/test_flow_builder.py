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


def test_build_flows_rolls_up_tls_metadata():
    base_time = datetime.now(tz=timezone.utc)
    packets = [
        PacketRecord(
            timestamp=base_time,
            src_ip="192.168.1.20",
            dst_ip="198.51.100.40",
            src_port=54000,
            dst_port=443,
            transport="TCP",
            protocol="TLS",
            length=120,
            tls={
                "looks_like_tls": True,
                "handshake_type": "client_hello",
                "sni": "alpha.example",
                "alpn_protocols": ["h2"],
                "ja3_like_fingerprint": "abc",
                "record_version": "3.1",
                "client_version": "3.3",
                "cipher_suites_sample": ["0x1301"],
            },
        ),
        PacketRecord(
            timestamp=base_time + timedelta(seconds=1),
            src_ip="192.168.1.20",
            dst_ip="198.51.100.40",
            src_port=54000,
            dst_port=443,
            transport="TCP",
            protocol="TLS",
            length=140,
            tls={
                "looks_like_tls": True,
                "handshake_type": "server_hello",
                "alpn_protocols": ["http/1.1"],
                "ja3_like_fingerprint": "def",
                "record_version": "3.3",
                "client_version": "3.3",
                "cipher_suites_sample": ["0x1302"],
            },
        ),
    ]

    flows = build_flows(packets)

    assert flows[0].metadata["handshake_seen"] is True
    assert flows[0].metadata["tls_record_count"] == 2
    assert flows[0].metadata["sni"] == "alpha.example"
    assert flows[0].metadata["alpn_protocols"] == ["h2", "http/1.1"]
    assert flows[0].metadata["ja3_like_fingerprints"] == ["abc", "def"]
