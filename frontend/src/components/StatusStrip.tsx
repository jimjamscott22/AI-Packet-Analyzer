import type { AnalysisJob } from "../types/api";

interface StatusStripProps {
  job: AnalysisJob | null;
}

export function StatusStrip({ job }: StatusStripProps) {
  return (
    <section className="status-strip">
      <div>
        <span>Status</span>
        <strong>{job?.status ?? "idle"}</strong>
      </div>
      <div>
        <span>Progress</span>
        <strong>{job ? `${Math.round(job.progress * 100)}%` : "0%"}</strong>
      </div>
      <div>
        <span>Packets</span>
        <strong>{job?.packet_count ?? 0}</strong>
      </div>
      <div>
        <span>Flows</span>
        <strong>{job?.flow_count ?? 0}</strong>
      </div>
    </section>
  );
}
