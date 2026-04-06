import asyncio

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status

from app.models.schemas import (
    AnalysisJobResponse,
    FindingListResponse,
    FlowDetail,
    FlowListResponse,
    JobSummary,
)
from app.services.analysis import run_analysis_job
from app.services.job_service import (
    create_job,
    get_flow_detail,
    get_findings,
    get_flows,
    get_job_or_404,
    get_summary,
)
from app.services.storage import save_upload

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


@router.post("", response_model=AnalysisJobResponse, status_code=status.HTTP_201_CREATED)
async def create_analysis_job(file: UploadFile = File(...)) -> AnalysisJobResponse:
    saved_upload = await save_upload(file)
    job = create_job(saved_upload.filename, saved_upload.stored_path)
    asyncio.create_task(run_analysis_job(job.id))
    return job


@router.get("/{job_id}", response_model=AnalysisJobResponse)
def read_job(job_id: str) -> AnalysisJobResponse:
    return get_job_or_404(job_id)


@router.get("/{job_id}/summary", response_model=JobSummary)
def read_summary(job_id: str) -> JobSummary:
    get_job_or_404(job_id)
    return get_summary(job_id)


@router.get("/{job_id}/findings", response_model=FindingListResponse)
def read_findings(job_id: str) -> FindingListResponse:
    get_job_or_404(job_id)
    return FindingListResponse(items=get_findings(job_id))


@router.get("/{job_id}/flows", response_model=FlowListResponse)
def read_flows(
    job_id: str,
    protocol: str | None = Query(default=None),
    search: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=25, ge=1, le=200),
) -> FlowListResponse:
    get_job_or_404(job_id)
    return get_flows(job_id, protocol=protocol, search=search, offset=offset, limit=limit)


@router.get("/{job_id}/flows/{flow_id}", response_model=FlowDetail)
def read_flow_detail(job_id: str, flow_id: str) -> FlowDetail:
    get_job_or_404(job_id)
    flow = get_flow_detail(job_id, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow
