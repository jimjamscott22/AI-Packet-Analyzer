import type { AnalysisJob, FindingRecord, FlowDetail, FlowListItem, JobSummary, PaginatedResponse } from "../types/api";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json() as Promise<T>;
}

export async function uploadPcap(file: File): Promise<AnalysisJob> {
  const formData = new FormData();
  formData.append("file", file);
  return request<AnalysisJob>("/jobs", { method: "POST", body: formData });
}

export function getJob(jobId: string): Promise<AnalysisJob> {
  return request<AnalysisJob>(`/jobs/${jobId}`);
}

export function getSummary(jobId: string): Promise<JobSummary> {
  return request<JobSummary>(`/jobs/${jobId}/summary`);
}

interface FindingQuery {
  severity?: string;
  source?: string;
  search?: string;
  offset?: number;
  limit?: number;
}

interface FlowQuery {
  protocol?: string;
  search?: string;
  offset?: number;
  limit?: number;
}

export async function getFindings(jobId: string, query: FindingQuery): Promise<PaginatedResponse<FindingRecord>> {
  const params = new URLSearchParams();
  if (query.severity && query.severity !== "ALL") {
    params.set("severity", query.severity);
  }
  if (query.source && query.source !== "ALL") {
    params.set("source", query.source);
  }
  if (query.search?.trim()) {
    params.set("search", query.search.trim());
  }
  params.set("offset", String(query.offset ?? 0));
  params.set("limit", String(query.limit ?? 25));
  return request<PaginatedResponse<FindingRecord>>(`/jobs/${jobId}/findings?${params.toString()}`);
}

export async function getFlows(jobId: string, query: FlowQuery): Promise<PaginatedResponse<FlowListItem>> {
  const params = new URLSearchParams();
  if (query.protocol && query.protocol !== "ALL") {
    params.set("protocol", query.protocol);
  }
  if (query.search?.trim()) {
    params.set("search", query.search.trim());
  }
  params.set("offset", String(query.offset ?? 0));
  params.set("limit", String(query.limit ?? 25));
  return request<PaginatedResponse<FlowListItem>>(`/jobs/${jobId}/flows?${params.toString()}`);
}

export function getFlowDetail(jobId: string, flowId: string): Promise<FlowDetail> {
  return request<FlowDetail>(`/jobs/${jobId}/flows/${flowId}`);
}
