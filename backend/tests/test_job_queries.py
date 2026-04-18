from dataclasses import replace

from app.core.config import Settings
from app.db import database
from app.services.job_service import create_job, get_findings, get_flows, replace_job_results


def test_get_findings_supports_filters_pagination_and_deterministic_order(tmp_path, monkeypatch):
    settings = replace(
        Settings(),
        data_dir=tmp_path,
        upload_dir=tmp_path / "uploads",
        db_path=tmp_path / "packet_analyzer.db",
    )
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(database, "get_settings", lambda: settings)
    database.init_db()

    job = create_job("sample.pcap", str(tmp_path / "sample.pcap"))
    replace_job_results(
        job.id,
        [
            {
                "id": "flow-1",
                "protocol": "TLS",
                "src_ip": "10.0.0.5",
                "src_port": 54000,
                "dst_ip": "198.51.100.10",
                "dst_port": 443,
                "first_seen": None,
                "last_seen": None,
                "packet_count": 4,
                "byte_count": 600,
                "duration_seconds": 4.0,
                "score": 0.72,
                "classification": "suspicious_tls_pattern",
                "directionality": "outbound",
                "metadata": {"sni": "suspicious.example", "ja3_like_fingerprints": ["abc123"]},
                "evidence": ["visible handshake"],
            }
        ],
        [
            {
                "id": "finding-medium-a",
                "type": "needs_review",
                "severity": "medium",
                "confidence": 0.7,
                "title": "Alpha medium",
                "summary": "Contains suspicious.example",
                "source": "heuristic",
                "flow_ids": ["flow-1"],
                "evidence": ["alpha evidence"],
            },
            {
                "id": "finding-high",
                "type": "suspicious_tls_pattern",
                "severity": "high",
                "confidence": 0.6,
                "title": "Beta high",
                "summary": "Escalated",
                "source": "llm",
                "flow_ids": ["flow-1"],
                "evidence": ["llm evidence"],
            },
            {
                "id": "finding-medium-b",
                "type": "needs_review",
                "severity": "medium",
                "confidence": 0.7,
                "title": "Beta medium",
                "summary": "Contains another match",
                "source": "heuristic",
                "flow_ids": ["flow-1"],
                "evidence": ["beta evidence"],
            },
        ],
    )

    page = get_findings(job.id, severity=None, source=None, search=None, offset=0, limit=2)
    assert page.total == 3
    assert [item.id for item in page.items] == ["finding-high", "finding-medium-a"]

    heuristic_only = get_findings(job.id, severity="medium", source="heuristic", search="match", offset=0, limit=10)
    assert heuristic_only.total == 1
    assert [item.id for item in heuristic_only.items] == ["finding-medium-b"]


def test_get_flows_supports_metadata_and_classification_search(tmp_path, monkeypatch):
    settings = replace(
        Settings(),
        data_dir=tmp_path,
        upload_dir=tmp_path / "uploads",
        db_path=tmp_path / "packet_analyzer.db",
    )
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(database, "get_settings", lambda: settings)
    database.init_db()

    job = create_job("flows.pcap", str(tmp_path / "flows.pcap"))
    replace_job_results(
        job.id,
        [
            {
                "id": "flow-a",
                "protocol": "TLS",
                "src_ip": "10.0.0.10",
                "src_port": 51000,
                "dst_ip": "203.0.113.5",
                "dst_port": 443,
                "first_seen": None,
                "last_seen": None,
                "packet_count": 3,
                "byte_count": 300,
                "duration_seconds": 2.0,
                "score": 0.9,
                "classification": "suspicious_tls_pattern",
                "directionality": "outbound",
                "metadata": {"sni": "hidden.example", "alpn_protocols": ["h2"]},
                "evidence": [],
            },
            {
                "id": "flow-b",
                "protocol": "TLS",
                "src_ip": "10.0.0.11",
                "src_port": 51001,
                "dst_ip": "203.0.113.6",
                "dst_port": 443,
                "first_seen": None,
                "last_seen": None,
                "packet_count": 5,
                "byte_count": 500,
                "duration_seconds": 5.0,
                "score": 0.4,
                "classification": "normal",
                "directionality": "outbound",
                "metadata": {"sni": "benign.example"},
                "evidence": [],
            },
        ],
        [],
    )

    classification_match = get_flows(job.id, protocol="TLS", search="suspicious_tls_pattern", offset=0, limit=10)
    assert classification_match.total == 1
    assert [item.id for item in classification_match.items] == ["flow-a"]

    metadata_match = get_flows(job.id, protocol="TLS", search="hidden.example", offset=0, limit=10)
    assert metadata_match.total == 1
    assert [item.id for item in metadata_match.items] == ["flow-a"]

    page = get_flows(job.id, protocol="TLS", search="", offset=0, limit=1)
    assert page.total == 2
    assert [item.id for item in page.items] == ["flow-a"]
