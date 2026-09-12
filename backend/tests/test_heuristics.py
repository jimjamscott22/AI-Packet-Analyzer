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
    dns_finding = next(item for item in findings if item["type"] == "suspicious_dns_tunneling")
    assert dns_finding["evidence"][0].startswith("High-entropy")
    assert any("20 queries" in line for line in dns_finding["evidence"])


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
    beacon = next(item for item in findings if item["type"] == "suspicious_beaconing")
    assert beacon["evidence"][0].startswith("Connection timing appears periodic")


def test_tls_heuristic_uses_richer_metadata():
    flow = FlowFeature(
        id="tls-2",
        protocol="TLS",
        src_ip="192.168.1.30",
        src_port=53000,
        dst_ip="198.51.100.23",
        dst_port=443,
        first_seen=None,
        last_seen=None,
        duration_seconds=8.0,
        packet_count=4,
        byte_count=480,
        directionality="outbound",
        metadata={
            "packet_timestamps": [0.0, 2.0, 4.0, 6.0],
            "looks_like_tls": True,
            "handshake_seen": False,
            "sni": None,
            "alpn_protocols": [],
            "ja3_like_fingerprints": ["abc", "def"],
        },
    )

    flows, findings = apply_heuristics([flow])

    assert flows[0].classification in {"suspicious_beaconing", "suspicious_tls_pattern"}
    assert any(item["type"] == "suspicious_tls_pattern" for item in findings)
    tls_finding = next(item for item in findings if item["type"] == "suspicious_tls_pattern")
    assert tls_finding["evidence"][0].startswith("TLS flow exposes neither SNI nor ALPN")


def test_tls_heuristic_leaves_benign_visible_handshake_normal():
    flow = FlowFeature(
        id="tls-3",
        protocol="TLS",
        src_ip="192.168.1.31",
        src_port=53001,
        dst_ip="198.51.100.24",
        dst_port=443,
        first_seen=None,
        last_seen=None,
        duration_seconds=90.0,
        packet_count=20,
        byte_count=12000,
        directionality="outbound",
        metadata={
            "packet_timestamps": [0.0, 3.0, 11.0, 18.0, 30.0, 47.0, 60.0, 82.0],
            "looks_like_tls": True,
            "handshake_seen": True,
            "sni": "cdn.example",
            "alpn_protocols": ["h2"],
            "ja3_like_fingerprints": ["stable"],
        },
    )

    flows, findings = apply_heuristics([flow])

    assert flows[0].classification == "normal"
    assert findings[0]["type"] == "normal"


def test_https_port_alone_does_not_create_tls_finding():
    flow = FlowFeature(
        id="tls-4",
        protocol="TLS",
        src_ip="192.168.1.40",
        src_port=54000,
        dst_ip="198.51.100.40",
        dst_port=443,
        first_seen=None,
        last_seen=None,
        duration_seconds=45.0,
        packet_count=12,
        byte_count=8000,
        directionality="outbound",
        metadata={
            "packet_timestamps": [0.0, 5.0, 18.0, 29.0],
            "looks_like_tls": True,
            "handshake_seen": True,
            "sni": "shop.example",
            "alpn_protocols": ["h2"],
            "ja3_like_fingerprints": ["stable"],
        },
    )

    _, findings = apply_heuristics([flow])

    assert findings[0]["type"] == "normal"


def test_related_same_host_findings_are_grouped():
    flows = [
        FlowFeature(
            id=f"dns-{index}",
            protocol="DNS",
            src_ip="192.168.1.20",
            src_port=51000 + index,
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
        for index in range(2)
    ]

    _, findings = apply_heuristics(flows)

    dns_findings = [item for item in findings if item["type"] == "suspicious_dns_tunneling"]
    assert len(dns_findings) == 1
    assert set(dns_findings[0]["flow_ids"]) == {"dns-0", "dns-1"}
    assert "Grouped 2 related flows" in dns_findings[0]["summary"]
