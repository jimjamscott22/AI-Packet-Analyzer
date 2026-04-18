export type JobStatus = "queued" | "processing" | "completed" | "processing_error";

export interface AnalysisJob {
  id: string;
  filename: string;
  status: JobStatus;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  error_message?: string | null;
  progress: number;
  packet_count: number;
  flow_count: number;
}

export interface SummaryMetric {
  protocol?: string;
  host?: string;
  severity?: string;
  count?: number;
  bytes?: number;
}

export interface JobSummary {
  job_id: string;
  status: JobStatus;
  packet_count: number;
  flow_count: number;
  finding_count: number;
  top_protocols: SummaryMetric[];
  top_talkers: SummaryMetric[];
  severities: SummaryMetric[];
  llm_enabled: boolean;
}

export interface FindingRecord {
  id: string;
  type: string;
  severity: string;
  confidence: number;
  title: string;
  summary: string;
  source: "heuristic" | "llm";
  flow_ids: string[];
  evidence: string[];
  recommended_action?: string | null;
}

export interface PaginatedResponse<T> {
  total: number;
  items: T[];
}

export interface FlowListItem {
  id: string;
  protocol: string;
  src_ip: string;
  src_port?: number | null;
  dst_ip: string;
  dst_port?: number | null;
  packet_count: number;
  byte_count: number;
  duration_seconds: number;
  score: number;
  classification: string;
}

export interface LLMDecision {
  model: string;
  prompt_version: string;
  classification: string;
  rationale: string;
  confidence: number;
  recommended_action: string;
  token_count?: number | null;
  latency_ms?: number | null;
}

export interface FlowDetail extends FlowListItem {
  first_seen?: string | null;
  last_seen?: string | null;
  directionality: string;
  metadata: Record<string, unknown>;
  evidence: string[];
  llm_decision?: LLMDecision | null;
}
