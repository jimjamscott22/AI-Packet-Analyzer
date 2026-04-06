from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


JobStatus = Literal["queued", "processing", "completed", "processing_error"]
FindingSource = Literal["heuristic", "llm"]


class AnalysisJobResponse(BaseModel):
    id: str
    filename: str
    status: JobStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str | None = None
    progress: float = 0.0
    packet_count: int = 0
    flow_count: int = 0


class FindingRecord(BaseModel):
    id: str
    type: str
    severity: str
    confidence: float
    title: str
    summary: str
    source: FindingSource
    flow_ids: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str | None = None


class FindingListResponse(BaseModel):
    items: list[FindingRecord]


class FlowListItem(BaseModel):
    id: str
    protocol: str
    src_ip: str
    src_port: int | None = None
    dst_ip: str
    dst_port: int | None = None
    packet_count: int
    byte_count: int
    duration_seconds: float
    score: float
    classification: str


class LLMDecision(BaseModel):
    model: str
    prompt_version: str
    classification: str
    rationale: str
    confidence: float
    recommended_action: str
    token_count: int | None = None
    latency_ms: float | None = None


class FlowDetail(FlowListItem):
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    directionality: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    llm_decision: LLMDecision | None = None


class FlowListResponse(BaseModel):
    total: int
    items: list[FlowListItem]


class JobSummary(BaseModel):
    job_id: str
    status: JobStatus
    packet_count: int = 0
    flow_count: int = 0
    finding_count: int = 0
    top_protocols: list[dict[str, Any]] = Field(default_factory=list)
    top_talkers: list[dict[str, Any]] = Field(default_factory=list)
    severities: list[dict[str, Any]] = Field(default_factory=list)
    llm_enabled: bool = False
