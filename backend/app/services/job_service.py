from __future__ import annotations

from datetime import datetime, timezone
import json
import sqlite3
from uuid import uuid4

from fastapi import HTTPException

from app.core.config import get_settings
from app.db.database import get_connection
from app.models.schemas import (
    AnalysisJobResponse,
    FindingRecord,
    FlowDetail,
    FlowListItem,
    FlowListResponse,
    JobSummary,
    LLMDecision,
)


def create_job(filename: str, stored_path: str) -> AnalysisJobResponse:
    job_id = str(uuid4())
    created_at = _now()
    connection = get_connection()
    connection.execute(
        """
        INSERT INTO jobs (id, filename, stored_path, status, created_at, progress, packet_count, flow_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (job_id, filename, stored_path, "queued", created_at, 0.0, 0, 0),
    )
    connection.commit()
    connection.close()
    return get_job_or_404(job_id)


def get_job_or_404(job_id: str) -> AnalysisJobResponse:
    connection = get_connection()
    row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    connection.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return AnalysisJobResponse(**dict(row))


def mark_job_processing(job_id: str) -> None:
    _execute(
        "UPDATE jobs SET status = ?, started_at = ?, progress = ? WHERE id = ?",
        ("processing", _now(), 0.1, job_id),
    )


def update_job_progress(job_id: str, *, progress: float, packet_count: int | None = None, flow_count: int | None = None) -> None:
    connection = get_connection()
    if packet_count is None and flow_count is None:
        connection.execute("UPDATE jobs SET progress = ? WHERE id = ?", (progress, job_id))
    else:
        connection.execute(
            "UPDATE jobs SET progress = ?, packet_count = COALESCE(?, packet_count), flow_count = COALESCE(?, flow_count) WHERE id = ?",
            (progress, packet_count, flow_count, job_id),
        )
    connection.commit()
    connection.close()


def mark_job_complete(job_id: str, *, packet_count: int, flow_count: int) -> None:
    _execute(
        "UPDATE jobs SET status = ?, finished_at = ?, progress = ?, packet_count = ?, flow_count = ? WHERE id = ?",
        ("completed", _now(), 1.0, packet_count, flow_count, job_id),
    )


def mark_job_failed(job_id: str, error_message: str) -> None:
    _execute(
        "UPDATE jobs SET status = ?, finished_at = ?, progress = ?, error_message = ? WHERE id = ?",
        ("processing_error", _now(), 1.0, error_message, job_id),
    )


def get_job_path(job_id: str) -> str:
    connection = get_connection()
    row = connection.execute("SELECT stored_path FROM jobs WHERE id = ?", (job_id,)).fetchone()
    connection.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return str(row["stored_path"])


def replace_job_results(job_id: str, flows: list[dict], findings: list[dict]) -> None:
    connection = get_connection()
    connection.execute("DELETE FROM flows WHERE job_id = ?", (job_id,))
    connection.execute("DELETE FROM findings WHERE job_id = ?", (job_id,))
    connection.executemany(
        """
        INSERT INTO flows (
            id, job_id, protocol, src_ip, src_port, dst_ip, dst_port, first_seen, last_seen,
            packet_count, byte_count, duration_seconds, score, classification, directionality,
            metadata_json, evidence_json, llm_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                flow["id"],
                job_id,
                flow["protocol"],
                flow["src_ip"],
                flow["src_port"],
                flow["dst_ip"],
                flow["dst_port"],
                flow["first_seen"],
                flow["last_seen"],
                flow["packet_count"],
                flow["byte_count"],
                flow["duration_seconds"],
                flow["score"],
                flow["classification"],
                flow["directionality"],
                json.dumps(flow["metadata"]),
                json.dumps(flow["evidence"]),
                json.dumps(flow["llm_decision"]) if flow.get("llm_decision") else None,
            )
            for flow in flows
        ],
    )
    connection.executemany(
        """
        INSERT INTO findings (
            id, job_id, type, severity, confidence, title, summary, source, flow_ids_json,
            evidence_json, recommended_action
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                finding["id"],
                job_id,
                finding["type"],
                finding["severity"],
                finding["confidence"],
                finding["title"],
                finding["summary"],
                finding["source"],
                json.dumps(finding["flow_ids"]),
                json.dumps(finding["evidence"]),
                finding.get("recommended_action"),
            )
            for finding in findings
        ],
    )
    connection.commit()
    connection.close()


def get_findings(job_id: str) -> list[FindingRecord]:
    connection = get_connection()
    rows = connection.execute("SELECT * FROM findings WHERE job_id = ? ORDER BY confidence DESC", (job_id,)).fetchall()
    connection.close()
    return [
        FindingRecord(
            id=row["id"],
            type=row["type"],
            severity=row["severity"],
            confidence=row["confidence"],
            title=row["title"],
            summary=row["summary"],
            source=row["source"],
            flow_ids=json.loads(row["flow_ids_json"]),
            evidence=json.loads(row["evidence_json"]),
            recommended_action=row["recommended_action"],
        )
        for row in rows
    ]


def get_flows(job_id: str, *, protocol: str | None, search: str | None, offset: int, limit: int) -> FlowListResponse:
    connection = get_connection()
    conditions = ["job_id = ?"]
    params: list[object] = [job_id]
    if protocol:
        conditions.append("protocol = ?")
        params.append(protocol.upper())
    if search:
        conditions.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])

    where_clause = " AND ".join(conditions)
    total = connection.execute(f"SELECT COUNT(*) FROM flows WHERE {where_clause}", params).fetchone()[0]
    rows = connection.execute(
        f"""
        SELECT * FROM flows
        WHERE {where_clause}
        ORDER BY score DESC, packet_count DESC, protocol ASC
        LIMIT ? OFFSET ?
        """,
        (*params, limit, offset),
    ).fetchall()
    connection.close()
    return FlowListResponse(total=total, items=[_row_to_flow_list_item(row) for row in rows])


def get_flow_detail(job_id: str, flow_id: str) -> FlowDetail | None:
    connection = get_connection()
    row = connection.execute("SELECT * FROM flows WHERE job_id = ? AND id = ?", (job_id, flow_id)).fetchone()
    connection.close()
    if row is None:
        return None
    llm_json = json.loads(row["llm_json"]) if row["llm_json"] else None
    return FlowDetail(
        **_row_to_flow_list_item(row).model_dump(),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        directionality=row["directionality"],
        metadata=json.loads(row["metadata_json"]),
        evidence=json.loads(row["evidence_json"]),
        llm_decision=LLMDecision(**llm_json) if llm_json else None,
    )


def get_summary(job_id: str) -> JobSummary:
    job = get_job_or_404(job_id)
    settings = get_settings()
    connection = get_connection()
    top_protocols = [
        {"protocol": row["protocol"], "count": row["count"]}
        for row in connection.execute(
            "SELECT protocol, COUNT(*) AS count FROM flows WHERE job_id = ? GROUP BY protocol ORDER BY count DESC LIMIT 5",
            (job_id,),
        ).fetchall()
    ]
    top_talkers = [
        {"host": row["host"], "bytes": row["bytes"]}
        for row in connection.execute(
            """
            SELECT src_ip AS host, SUM(byte_count) AS bytes
            FROM flows
            WHERE job_id = ?
            GROUP BY src_ip
            ORDER BY bytes DESC
            LIMIT 5
            """,
            (job_id,),
        ).fetchall()
    ]
    severities = [
        {"severity": row["severity"], "count": row["count"]}
        for row in connection.execute(
            "SELECT severity, COUNT(*) AS count FROM findings WHERE job_id = ? GROUP BY severity ORDER BY count DESC",
            (job_id,),
        ).fetchall()
    ]
    finding_count = connection.execute("SELECT COUNT(*) FROM findings WHERE job_id = ?", (job_id,)).fetchone()[0]
    connection.close()
    return JobSummary(
        job_id=job_id,
        status=job.status,
        packet_count=job.packet_count,
        flow_count=job.flow_count,
        finding_count=finding_count,
        top_protocols=top_protocols,
        top_talkers=top_talkers,
        severities=severities,
        llm_enabled=settings.llm_enabled,
    )


def _row_to_flow_list_item(row: sqlite3.Row) -> FlowListItem:
    return FlowListItem(
        id=row["id"],
        protocol=row["protocol"],
        src_ip=row["src_ip"],
        src_port=row["src_port"],
        dst_ip=row["dst_ip"],
        dst_port=row["dst_port"],
        packet_count=row["packet_count"],
        byte_count=row["byte_count"],
        duration_seconds=row["duration_seconds"],
        score=row["score"],
        classification=row["classification"],
    )


def _execute(query: str, params: tuple[object, ...]) -> None:
    connection = get_connection()
    connection.execute(query, params)
    connection.commit()
    connection.close()


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()
