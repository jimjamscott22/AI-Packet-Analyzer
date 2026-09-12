from app.detectors.heuristics import apply_heuristics
from app.parsers.scapy_parser import ScapyPacketParser
from app.services.flow_builder import build_flows
from pcap_factory import (
    write_beaconing_tls_pcap,
    write_benign_dns_pcap,
    write_benign_tls_pcap,
    write_dns_tunnel_pcap,
    write_suspicious_tls_pcap,
)


def _analyze(path):
    packets = ScapyPacketParser().parse(str(path))
    flows = build_flows(packets)
    return apply_heuristics(flows)


def test_dns_tunnel_pcap_produces_tunneling_finding(tmp_path):
    path = write_dns_tunnel_pcap(tmp_path / "dns-tunnel.pcap")
    flows, findings = _analyze(path)

    assert flows
    assert any(item["type"] == "suspicious_dns_tunneling" for item in findings)
    assert flows[0].metadata["query_names"]


def test_benign_dns_pcap_stays_normal(tmp_path):
    path = write_benign_dns_pcap(tmp_path / "dns-benign.pcap")
    flows, findings = _analyze(path)

    assert flows
    assert all(flow.classification == "normal" for flow in flows)
    assert findings[0]["type"] == "normal"


def test_beaconing_tls_pcap_produces_beacon_or_tls_finding(tmp_path):
    path = write_beaconing_tls_pcap(tmp_path / "tls-beacon.pcap")
    flows, findings = _analyze(path)

    assert flows[0].protocol == "TLS"
    assert any(item["type"] in {"suspicious_beaconing", "suspicious_tls_pattern"} for item in findings)


def test_suspicious_tls_pcap_flags_opaque_handshake(tmp_path):
    path = write_suspicious_tls_pcap(tmp_path / "tls-suspicious.pcap")
    flows, findings = _analyze(path)

    assert flows[0].metadata.get("looks_like_tls") is True
    assert any(item["type"] == "suspicious_tls_pattern" for item in findings)


def test_benign_tls_pcap_keeps_visible_handshake_normal(tmp_path):
    path = write_benign_tls_pcap(tmp_path / "tls-benign.pcap")
    flows, findings = _analyze(path)

    assert flows[0].metadata.get("sni") == "cdn.example"
    assert flows[0].metadata.get("handshake_seen") is True
    assert flows[0].classification == "normal"
    assert findings[0]["type"] == "normal"
