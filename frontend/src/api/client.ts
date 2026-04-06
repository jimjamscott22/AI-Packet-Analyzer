import type { AnalysisJob, FindingRecord, FlowDetail, FlowListItem, JobSummary } from "../types/api";

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

export async function getFindings(jobId: string): Promise<FindingRecord[]> {
  const payload = await request<{ items: FindingRecord[] }>(`/jobs/${jobId}/findings`);
  return payload.items;
}

export async function getFlows(jobId: string, protocol: string, search: string): Promise<FlowListItem[]> {
  const params = new URLSearchParams();
  if (protocol !== "ALL") {
    params.set("protocol", protocol);
  }
  if (search.trim()) {
    params.set("search", search.trim());
  }
  const payload = await request<{ items: FlowListItem[] }>(`/jobs/${jobId}/flows?${params.toString()}`);
  return payload.items;
}

export function getFlowDetail(jobId: string, flowId: string): Promise<FlowDetail> {
  return request<FlowDetail>(`/jobs/${jobId}/flows/${flowId}`);
}
