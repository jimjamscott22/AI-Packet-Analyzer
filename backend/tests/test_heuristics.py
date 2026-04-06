from app.detectors.heuristics import FlowFeature, apply_heuristics


def test_dns_tunneling_heuristic_flags_high_entropy_queries():
    flow = FlowFeature(
        id="dns-1",
        protocol="DNS",
        src_ip="192.168.1.20",
        src_port=51000,
        dst_ip="1.1.1.1",
        dst_port=53,
        first_seen=None,
        last_seen=None,
        duration_seconds=12.0,
        packet_count=20,
        byte_count=4000,
        directionality="outbound",
        metadata={
            "query_names": [f"x{i}q9v2b8c7d6e5f4g3h2.example.com" for i in range(20)],
            "query_types": [16] * 6,
        },
    )

    flows, findings = apply_heuristics([flow])

    assert flows[0].classification == "suspicious_dns_tunneling"
    assert any(item["type"] == "suspicious_dns_tunneling" for item in findings)


def test_beaconing_heuristic_flags_periodic_tls():
    flow = FlowFeature(
        id="tls-1",
        protocol="TLS",
        src_ip="192.168.1.15",
        src_port=52000,
        dst_ip="198.51.100.22",
        dst_port=443,
        first_seen=None,
        last_seen=None,
        duration_seconds=20.0,
        packet_count=5,
        byte_count=700,
        directionality="outbound",
        metadata={
            "packet_timestamps": [0.0, 10.0, 20.0, 30.0, 40.0],
            "looks_like_tls": True,
            "sni": None,
        },
    )

    flows, findings = apply_heuristics([flow])

    assert flows[0].classification in {"suspicious_beaconing", "suspicious_tls_pattern"}
    assert any(item["type"] in {"suspicious_beaconing", "suspicious_tls_pattern"} for item in findings)
