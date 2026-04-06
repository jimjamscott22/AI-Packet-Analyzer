from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import math
from statistics import mean, pstdev
from typing import Any
from uuid import uuid4


@dataclass
class FlowFeature:
    id: str
    protocol: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    first_seen: str | None
    last_seen: str | None
    duration_seconds: float
    packet_count: int
    byte_count: int
    directionality: str
    metadata: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    classification: str = "normal"
    evidence: list[str] = field(default_factory=list)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def apply_heuristics(flows: list[FlowFeature]) -> tuple[list[FlowFeature], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    outbound_counts = Counter(flow.src_ip for flow in flows)

    for flow in flows:
        evidence: list[str] = []
        score = 0.0
        classification = "normal"

        if flow.protocol == "DNS":
            query_names: list[str] = flow.metadata.get("query_names", [])
            unique_subdomains = len(set(query_names))
            average_length = mean([len(item) for item in query_names]) if query_names else 0.0
            entropy = mean([_shannon_entropy(item) for item in query_names]) if query_names else 0.0
            query_type_counts = Counter(flow.metadata.get("query_types", []))

            if flow.packet_count >= 15:
                score += 0.25
                evidence.append("High DNS query count within a single flow.")
            if average_length >= 40:
                score += 0.25
                evidence.append("Long DNS query names increase tunneling suspicion.")
            if entropy >= 3.6:
                score += 0.3
                evidence.append("High-entropy labels suggest encoded subdomains.")
            if unique_subdomains >= 10:
                score += 0.2
                evidence.append("Large number of unique subdomains observed.")
            if query_type_counts.get(16, 0) >= 3:
                score += 0.15
                evidence.append("Repeated TXT queries observed.")

            if score >= 0.6:
                classification = "suspicious_dns_tunneling"
                findings.append(
                    _finding(
                        job_flow=flow,
                        finding_type=classification,
                        severity="high" if score >= 0.8 else "medium",
                        confidence=min(score, 0.99),
                        title="Possible DNS tunneling",
                        summary="Flow exhibits high-volume, long, and high-entropy DNS queries.",
                        evidence=evidence,
                    )
                )

        if flow.protocol in {"HTTP", "TLS"}:
            timestamps = flow.metadata.get("packet_timestamps", [])
            if len(timestamps) >= 4:
                intervals = [timestamps[index + 1] - timestamps[index] for index in range(len(timestamps) - 1)]
                avg_interval = mean(intervals)
                interval_stdev = pstdev(intervals) if len(intervals) > 1 else 0.0
                if 1.0 <= avg_interval <= 120.0 and interval_stdev <= max(avg_interval * 0.15, 1.0):
                    score += 0.45
                    evidence.append("Connection timing appears periodic.")

            average_packet_size = flow.byte_count / max(flow.packet_count, 1)
            if average_packet_size <= 220:
                score += 0.2
                evidence.append("Small, regular bursts resemble beaconing.")

            if flow.packet_count <= 8 and flow.duration_seconds <= 30:
                score += 0.15
                evidence.append("Short-lived repetitive session.")

            if outbound_counts[flow.src_ip] >= 8 and flow.protocol == "TLS":
                score += 0.1
                evidence.append("Host initiates many outbound sessions.")

            if score >= 0.6:
                classification = "suspicious_beaconing"
                findings.append(
                    _finding(
                        job_flow=flow,
                        finding_type=classification,
                        severity="high" if score >= 0.8 else "medium",
                        confidence=min(score, 0.99),
                        title="Possible command-and-control beaconing",
                        summary="Timing and packet-size regularity resemble automated callback traffic.",
                        evidence=evidence,
                    )
                )

        if flow.protocol == "TLS":
            short_sessions = flow.packet_count <= 6 and flow.duration_seconds <= 20
            if short_sessions:
                score += 0.2
                evidence.append("Short TLS session with little payload exchange.")
            if not flow.metadata.get("sni"):
                score += 0.15
                evidence.append("SNI missing from visible metadata.")
            if flow.metadata.get("looks_like_tls") and flow.dst_port == 443:
                score += 0.1
            if flow.score < score:
                flow.score = score
            if flow.classification == "normal" and score >= 0.45:
                flow.classification = "suspicious_tls_pattern"
                flow.evidence = list(dict.fromkeys(flow.evidence + evidence))
                findings.append(
                    _finding(
                        job_flow=flow,
                        finding_type="suspicious_tls_pattern",
                        severity="medium",
                        confidence=min(score, 0.85),
                        title="Suspicious TLS pattern",
                        summary="TLS metadata indicates repetitive, short, or opaque sessions worth review.",
                        evidence=evidence,
                    )
                )

        if score > flow.score:
            flow.score = score
        if classification != "normal":
            flow.classification = classification
        flow.evidence = list(dict.fromkeys(flow.evidence + evidence))

    if not findings:
        findings.append(
            {
                "id": str(uuid4()),
                "type": "normal",
                "severity": "info",
                "confidence": 0.95,
                "title": "No high-confidence suspicious patterns detected",
                "summary": "Traffic did not exceed the heuristic thresholds configured for v1.",
                "source": "heuristic",
                "flow_ids": [],
                "evidence": ["No DNS tunneling, beaconing, or TLS anomalies crossed scoring thresholds."],
                "recommended_action": "Review top talkers and protocols for context if deeper analysis is needed.",
            }
        )

    return flows, findings


def _finding(
    *,
    job_flow: FlowFeature,
    finding_type: str,
    severity: str,
    confidence: float,
    title: str,
    summary: str,
    evidence: list[str],
) -> dict[str, Any]:
    return {
        "id": str(uuid4()),
        "type": finding_type,
        "severity": severity,
        "confidence": round(confidence, 2),
        "title": title,
        "summary": summary,
        "source": "heuristic",
        "flow_ids": [job_flow.id],
        "evidence": evidence,
        "recommended_action": "Inspect the related flow and corroborate with endpoint or DNS logs.",
    }
