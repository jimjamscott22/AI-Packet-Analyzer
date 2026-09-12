from __future__ import annotations

from collections import Counter, defaultdict
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


def _score(signals: list[tuple[float, str]]) -> float:
    return round(sum(weight for weight, _ in signals), 4)


def _evidence(signals: list[tuple[float, str]]) -> list[str]:
    return [text for _, text in sorted(signals, key=lambda item: (-item[0], item[1]))]


def apply_heuristics(flows: list[FlowFeature]) -> tuple[list[FlowFeature], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    outbound_counts = Counter(flow.src_ip for flow in flows)

    for flow in flows:
        dns_signals: list[tuple[float, str]] = []
        beacon_signals: list[tuple[float, str]] = []
        tls_signals: list[tuple[float, str]] = []
        classification = "normal"

        if flow.protocol == "DNS":
            query_names: list[str] = flow.metadata.get("query_names", [])
            unique_subdomains = len(set(query_names))
            average_length = mean([len(item) for item in query_names]) if query_names else 0.0
            entropy = mean([_shannon_entropy(item) for item in query_names]) if query_names else 0.0
            query_type_counts = Counter(flow.metadata.get("query_types", []))

            if flow.packet_count >= 15:
                dns_signals.append(
                    (0.25, f"High DNS query count within a single flow ({flow.packet_count} queries).")
                )
            if average_length >= 40:
                dns_signals.append(
                    (0.3, f"Long DNS query names increase tunneling suspicion (avg {average_length:.1f} characters).")
                )
            if entropy >= 3.6:
                dns_signals.append(
                    (0.35, f"High-entropy labels suggest encoded subdomains (avg entropy {entropy:.2f}).")
                )
            if unique_subdomains >= 10:
                dns_signals.append(
                    (0.2, f"Large number of unique subdomains observed ({unique_subdomains}).")
                )
            if query_type_counts.get(16, 0) >= 3:
                txt_count = query_type_counts.get(16, 0)
                dns_signals.append((0.15, f"Repeated TXT queries observed ({txt_count})."))

            dns_score = _score(dns_signals)
            if dns_score >= 0.6:
                classification = "suspicious_dns_tunneling"
                evidence = _evidence(dns_signals)
                findings.append(
                    _finding(
                        job_flow=flow,
                        finding_type=classification,
                        severity="high" if dns_score >= 0.85 else "medium",
                        confidence=min(dns_score, 0.99),
                        title="Possible DNS tunneling",
                        summary=_summary("DNS tunneling indicators", evidence),
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
                    beacon_signals.append(
                        (
                            0.45,
                            f"Connection timing appears periodic (avg {avg_interval:.1f}s, stdev {interval_stdev:.1f}s).",
                        )
                    )

            average_packet_size = flow.byte_count / max(flow.packet_count, 1)
            if average_packet_size <= 220:
                beacon_signals.append(
                    (
                        0.2,
                        f"Small, regular bursts resemble beaconing (avg {average_packet_size:.0f} bytes/packet).",
                    )
                )

            if flow.packet_count <= 8 and flow.duration_seconds <= 30:
                beacon_signals.append(
                    (
                        0.15,
                        f"Short-lived repetitive session ({flow.packet_count} packets over {flow.duration_seconds:.1f}s).",
                    )
                )

            if outbound_counts[flow.src_ip] >= 8 and flow.protocol == "TLS":
                beacon_signals.append(
                    (0.15, f"Host initiates many outbound sessions ({outbound_counts[flow.src_ip]} from {flow.src_ip}).")
                )

            beacon_score = _score(beacon_signals)
            if beacon_score >= 0.6:
                classification = "suspicious_beaconing"
                evidence = _evidence(beacon_signals)
                findings.append(
                    _finding(
                        job_flow=flow,
                        finding_type=classification,
                        severity="high" if beacon_score >= 0.8 else "medium",
                        confidence=min(beacon_score, 0.99),
                        title="Possible command-and-control beaconing",
                        summary=_summary("Beaconing indicators", evidence),
                        evidence=evidence,
                    )
                )

        if flow.protocol == "TLS":
            short_sessions = flow.packet_count <= 6 and flow.duration_seconds <= 20
            if short_sessions:
                tls_signals.append(
                    (
                        0.15,
                        f"Short TLS session with little payload exchange ({flow.packet_count} packets, {flow.duration_seconds:.1f}s).",
                    )
                )
            has_sni = bool(flow.metadata.get("sni"))
            alpn_protocols = flow.metadata.get("alpn_protocols", [])
            handshake_seen = bool(flow.metadata.get("handshake_seen"))
            ja3_like_fingerprints = flow.metadata.get("ja3_like_fingerprints", [])

            if not has_sni and not alpn_protocols:
                tls_signals.append((0.25, "TLS flow exposes neither SNI nor ALPN metadata."))
            elif not has_sni:
                tls_signals.append((0.15, "SNI missing from visible metadata."))

            if not handshake_seen and flow.metadata.get("looks_like_tls"):
                tls_signals.append((0.2, "TLS records observed without a visible handshake."))

            if len(ja3_like_fingerprints) > 1 and short_sessions:
                tls_signals.append(
                    (
                        0.15,
                        f"Multiple JA3-like fingerprints observed across a short TLS flow ({len(ja3_like_fingerprints)}).",
                    )
                )

            tls_score = _score(tls_signals)
            if tls_score >= 0.45:
                if classification == "normal":
                    classification = "suspicious_tls_pattern"
                evidence = _evidence(tls_signals)
                findings.append(
                    _finding(
                        job_flow=flow,
                        finding_type="suspicious_tls_pattern",
                        severity="high" if tls_score >= 0.7 else "medium",
                        confidence=min(tls_score, 0.85),
                        title="Suspicious TLS pattern",
                        summary=_summary("TLS metadata anomalies", evidence),
                        evidence=evidence,
                    )
                )

        combined_signals = dns_signals + beacon_signals + tls_signals
        flow.score = _score(combined_signals)
        flow.classification = classification
        flow.evidence = _evidence(combined_signals)

    findings = _group_related_findings(flows, findings)
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


def _summary(prefix: str, evidence: list[str]) -> str:
    if not evidence:
        return f"{prefix} crossed the configured review threshold."
    strongest = evidence[0].rstrip(".")
    if len(evidence) == 1:
        return f"{prefix}: {strongest}."
    return f"{prefix}: {strongest}. Additional signals: {len(evidence) - 1}."


def _group_related_findings(flows: list[FlowFeature], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flow_index = {flow.id: flow for flow in flows}
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    passthrough: list[dict[str, Any]] = []

    for finding in findings:
        flow_ids = finding.get("flow_ids") or []
        if finding.get("source") != "heuristic" or finding.get("type") == "normal" or len(flow_ids) != 1:
            passthrough.append(finding)
            continue
        flow = flow_index.get(flow_ids[0])
        if flow is None:
            passthrough.append(finding)
            continue
        grouped[(finding["type"], finding["source"], flow.src_ip, flow.dst_ip)].append(finding)

    merged: list[dict[str, Any]] = []
    for items in grouped.values():
        if len(items) == 1:
            merged.append(items[0])
            continue
        primary = max(items, key=lambda item: (item.get("confidence", 0), len(item.get("evidence") or [])))
        flow_ids: list[str] = []
        evidence: list[str] = []
        for item in items:
            for flow_id in item.get("flow_ids") or []:
                if flow_id not in flow_ids:
                    flow_ids.append(flow_id)
            for line in item.get("evidence") or []:
                if line not in evidence:
                    evidence.append(line)
        severity = "high" if any(item.get("severity") == "high" for item in items) else primary["severity"]
        merged.append(
            {
                **primary,
                "severity": severity,
                "confidence": max(item.get("confidence", 0) for item in items),
                "flow_ids": flow_ids,
                "evidence": evidence,
                "summary": f"{primary['summary']} Grouped {len(flow_ids)} related flows between the same hosts.",
                "recommended_action": "Inspect the related flows and corroborate with endpoint or DNS logs.",
            }
        )
    return merged + passthrough


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
