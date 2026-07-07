from __future__ import annotations

from dataclasses import asdict

from app.core.config import get_settings
from app.detectors.heuristics import apply_heuristics
from app.llm.provider import OpenAICompatibleProvider
from app.parsers.scapy_parser import ScapyPacketParser
from app.services.flow_builder import build_flows
from app.services.job_service import (
    get_job_path,
    mark_job_complete,
    mark_job_failed,
    mark_job_processing,
    replace_job_results,
    update_job_progress,
)


async def run_analysis_job(job_id: str) -> None:
    parser = ScapyPacketParser()
    llm_provider = OpenAICompatibleProvider()
    settings = get_settings()

    try:
        mark_job_processing(job_id)
        file_path = get_job_path(job_id)

        packets = parser.parse(file_path)
        update_job_progress(job_id, progress=0.4, packet_count=len(packets))

        flows = build_flows(packets)
        update_job_progress(job_id, progress=0.65, packet_count=len(packets), flow_count=len(flows))

        scored_flows, findings = apply_heuristics(flows)
        update_job_progress(job_id, progress=0.8, packet_count=len(packets), flow_count=len(scored_flows))

        if settings.llm_enabled:
            ranked_flows = sorted(scored_flows, key=lambda item: item.score, reverse=True)[: settings.llm_max_flows]
            for flow in ranked_flows:
                llm_decision = await llm_provider.classify_flow(
                    {
                        "id": flow.id,
                        "protocol": flow.protocol,
                        "source": f"{flow.src_ip}:{flow.src_port or '-'}",
                        "destination": f"{flow.dst_ip}:{flow.dst_port or '-'}",
                        "packet_count": flow.packet_count,
                        "byte_count": flow.byte_count,
                        "duration_seconds": flow.duration_seconds,
                        "score": flow.score,
                        "classification": flow.classification,
                        "metadata": flow.metadata,
                        "evidence": flow.evidence,
                    }
                )
                if llm_decision:
                    flow.metadata["llm_reviewed"] = True
                    setattr(flow, "llm_decision", llm_decision)
                    if flow.classification == "normal" and llm_decision["classification"] != "normal":
                        flow.classification = llm_decision["classification"]
                        findings.append(
                            {
                                "id": f"llm-{flow.id}",
                                "type": llm_decision["classification"],
                                "severity": "medium",
                                "confidence": llm_decision["confidence"],
                                "title": "LLM review escalated this flow",
                                "summary": llm_decision["rationale"],
                                "source": "llm",
                                "flow_ids": [flow.id],
                                "evidence": flow.evidence,
                                "recommended_action": llm_decision["recommended_action"],
                            }
                        )

        serialized_flows = []
        for flow in scored_flows:
            payload = asdict(flow)
            payload["llm_decision"] = getattr(flow, "llm_decision", None)
            serialized_flows.append(payload)

        replace_job_results(job_id, serialized_flows, findings)
        mark_job_complete(job_id, packet_count=len(packets), flow_count=len(scored_flows))
    except Exception as exc:  # pragma: no cover - integration concern
        mark_job_failed(job_id, str(exc))
